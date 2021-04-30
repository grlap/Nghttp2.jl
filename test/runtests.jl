using Sockets
using OpenSSL
using Nghttp2
using Test

function read_all(io::IO)::Vector{UInt8}
    # Create IOBuffer and copy chunks until we read eof.
    result_stream = IOBuffer()

    while !eof(io)
        println("read_all from io: $(bytesavailable(io)) $(eof(io))")
        buffer_chunk = read(io)
        write(result_stream, buffer_chunk)
    end

    seekstart(result_stream)
    return read(result_stream)
end

function read_all_by_byte(io::IO)::Vector{UInt8}
    iob = IOBuffer()
    while !eof(io)
        c = read(io, UInt8)
        write(iob, c)
    end

    seek(iob, 0)

    return read(iob)
end

"""
    recv


"""

# Verifies calling into Nghttp library.
@testset "Nghttp2 " begin
    info = nghttp2_version()
    @test unsafe_string(info.proto_str) == "h2"
end

# Verifies creating unsecured Http2 connection
@testset "Http2 Connection" begin
    tcp_connection = connect("www.nghttp2.org", 80)

    client_session = Nghttp2.open(tcp_connection)

    # TODO empty request
    io = IOBuffer()
    stream_id1 = submit_request(
        client_session,
        io,
        [
            ":method" => "GET",
            ":path" => "/",
            ":scheme" => "http",
            ":authority" => "www.nghttp2.org",
            "accept" => "*/*",
            "user-agent" => "curl/7.75.0"
        ])

    stream1 = recv(client_session.session)
    stream2 = recv(client_session.session)
    stream3 = try_recv(client_session.session)

    @test isnothing(stream3)

    lengths = (length(read_all(stream2)), length(read_all(stream1)))
    @test minimum(lengths) == 6616
    @test maximum(lengths) == 39082

    header_lengths = (length(stream1.headers), length(stream2.headers))
    @test minimum(header_lengths) == 15
    @test maximum(header_lengths) == 19
end

@testset "Https2 Connection" begin
    println("===[Https]===")
    tcp_stream = connect("nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION | OpenSSL.SSL_OP_NO_TLSv1_2)
    result = OpenSSL.set_alpn(ssl_ctx, OpenSSL.UPDATE_HTTP2_ALPN)

    bio_stream = OpenSSL.BIOStream(tcp_stream)
    ssl_stream = SSLStream(ssl_ctx, bio_stream, bio_stream)

    # TODO expose connect
    result = connect(ssl_stream)

    client_session = Nghttp2.open(ssl_stream)

    iob = IOBuffer()
    stream_id1 = submit_request(
        client_session, iob,
        [
            ":method" => "GET",
            ":path" => "/",
            ":scheme" => "https",
            ":authority" => "www.nghttp2.org",
            "accept" => "*/*",
            "user-agent" => "curl/7.75.0"
        ])

    @show stream_id1

    stream1 = recv(client_session.session)
    stream2 = recv(client_session.session)

    println("[#TODO] => Wait too long")

    lengths = (length(read_all(stream1)), length(read_all_by_byte(stream2)))
    @test minimum(lengths) == 6616
    @test maximum(lengths) == 39082

    header_lengths = (length(stream1.headers), length(stream2.headers))
    @test minimum(header_lengths) == 16
    @test maximum(header_lengths) == 20

end

const DEFAULT_STATUS_200 = [":status" => "200"]
const DEFAULT_TRAILER = ["grpc-status" => "0"]

const DEFAULT_REQUEST = [
    ":method" => "POST",
    ":path" => "/default",
    ":authority" => "localhost:5000",
    ":scheme" => "http",
    "content-type" => "application/text"]

function test_server(socket::Sockets.TCPServer)
    accepted_socket = accept(socket)

    server_session = Nghttp2.from_accepted(accepted_socket)

    request_stream::Http2Stream = recv(server_session)

    println("==> test_server recv a stream")
    request_data = read_all(request_stream)
    println("test_server, received length: $(length(request_data))")

    send_buffer = IOBuffer(request_data)

    submit_response(
        request_stream,
        send_buffer,
        DEFAULT_STATUS_200)

    close(socket)
end

function test_server()
    socket = listen(5000)
    test_server(socket)
end

function test_client(request_io::IO = IOBuffer())
    tcp_connection = connect(5000)

    # Read all the input data to the buffer, use it later for comparision.
    request_data = read(request_io)
    request_iob = IOBuffer(request_data)

    client_session = Nghttp2.open(tcp_connection)

    stream_1 = submit_request(client_session, request_iob, DEFAULT_REQUEST)
    stream1 = recv(client_session.session)
    response_data = read_all(stream1)

    @test length(response_data) == length(request_data)
    @test response_data == request_data
end


function http_test()
    # /opt/homebrew/opt/curl/bin/curl --http2 --http2-prior-knowledge -i http://www.nghttp2.org
end

#@testset "Client/Server tests" begin
#    data = UInt8[0x00, 0x00, 0x00, 0x00, 0x11, 0x0a, 0x0f, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x65, 0x65, 0x74, 0x65, 0x72, 0x20, 0x32]
#    iob = IOBuffer(data)
#    f1 = @async test_server()
#    f2 = @async test_client(iob)
#
#    fetch(f2)
#    fetch(f1)
#end

@testset "Large request" begin
    iob = IOBuffer(repeat('a', 9*32768))

    f1 = @async test_server()
    f2 = @async test_client(iob)

    fetch(f2)
    fetch(f1)
end
