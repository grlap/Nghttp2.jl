using Sockets
using OpenSSL
using Nghttp2
using Test

function read_all(io::IO)::Vector{UInt8}
    # Create IOBuffer and copy chunks until we read eof.
    result_stream = IOBuffer()

    while !eof(io)
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

# TODO optimization
#function unsafe_read(s::IO, p::Ptr{UInt8}, n::UInt)
#   println("=> Base.read unsafe_read")
#   for i = 1:n
#    unsafe_store!(p, read(s, UInt8)::UInt8, i)
#   end
#    nothing
#end

"""
    recv

        session reading loop
            read and dispatch

            single Http2Session
                read()

            multiple entries from readstream
                until it is availabe

        ┌─────────────────┐
        │Http2Stream::read│─ ─ ─
        └─────────────────┘     │        session.read_lock
        ┌─────────────────┐      ─ ─ ▶    ╔════╗      ┌─────────────┐
        │Http2Stream::read│───────────────╣Lock╠─────▶│Session::read│
        └─────────────────┘      ─ ─ ▶    ╚════╝      └─────────────┘
        ┌─────────────────┐     │
        │Http2Stream::read│─ ─ ─
        └─────────────────┘

Less concurrent:

    single session lock
        single read, make sense anyway

    Http2Session::read
        read(session)
        wait for new 

    Session::recv
        read(session)
        wait for new session


Http2Stream::read
        acquire session.read_lock

        lock(success.lock) do
            read(session)
        end


        function read(session::Session)::Option{Http2Stream}

            any write: session.read_lock.notify()
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
    ":path" => "/MlosAgent.ExperimentManagerService/Echo",
    ":authority" => "localhost:5000",
    ":scheme" => "http",
    "content-type" => "application/grpc",
    "user-agent" => "grpc-dotnet/2.29.0.0",
    "grpc-accept-encoding" => "identity,gzip",
    "te" => "trailers"]

function test_server(socket::Sockets.TCPServer)
    accepted_socket = accept(socket)

    server_session = Nghttp2.from_accepted(accepted_socket)

    request_stream::Http2Stream = recv(server_session)
    @show request_stream

    send_buffer = IOBuffer(read(request_stream))
    println("===>sending $(send_buffer.data)")

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

function test_client()
    tcp_connection = connect(5000)

    client_session = Nghttp2.open(tcp_connection)

    data = UInt8[0x00, 0x00, 0x00, 0x00, 0x11, 0x0a, 0x0f, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x65, 0x65, 0x74, 0x65, 0x72, 0x20, 0x32]

    iob = IOBuffer(data)
    stream_1 = submit_request(client_session, iob, DEFAULT_REQUEST)
    stream1 = recv(client_session.session)
    response = read_all(stream1)

    @test response == data
end


function http_test()
    # /opt/homebrew/opt/curl/bin/curl --http2 --http2-prior-knowledge -i http://www.nghttp2.org
end

@testset "Client/Server tests" begin
    f1 = @async test_server()
    f2 = @async test_client()

    fetch(f1)
    fetch(f2)
end
#test_client()

#nghttp2_session_recv(session)

# wait_readnb(accepted_socket, 1)

# Client code.

#f1 = Nghttp2FrameHeader(0x000000000000000c, 0, 0x04, 0x00, 0x00)
#f2 = Nghttp2FrameHeader(0x0000000000000082, 1, 0x01, 0x04, 0x00)
#f3 = Nghttp2FrameHeader(0x0000000000000014, 1, 0x00, 0x00, 0x00)
#f4 = Nghttp2FrameHeader(0x0000000000000000, 1, 0x00, 0x01, 0x00)

# Redesign API
# Http2.Stream <: IO

