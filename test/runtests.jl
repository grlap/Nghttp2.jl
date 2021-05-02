using Sockets
using OpenSSL
using Nghttp2
using Test

include("testhelpers.jl")

"""
    Items:
[ ] send invalid headers
[ ] add faulty IO stream
[ ] add multiple requests

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

@testset "Large request" begin
    f1 = @async test_server()
    f2 = @async test_client(IOBuffer(repeat('a', 9*65536)))

    fetch(f1)
    @test fetch(f2) == true
end

@testset "Submit request on server session" begin
    # Create an server session and send a request.
    tcp_connection = connect("www.nghttp2.org", 80)

    server_session = Nghttp2.from_accepted(tcp_connection)

    try
        Nghttp2.send(
            server_session.session,
            IOBuffer(),
            [
                ":method" => "GET",
                ":path" => "/",
                ":scheme" => "http",
                ":authority" => "www.nghttp2.org",
                "accept" => "*/*",
                "user-agent" => "curl/7.75.0"
            ])
        @test 1 == 0
    catch e
        @test typeof(e) == Http2ProtocolException
        @test e.lib_error_code == Nghttp2.NGHTTP2_ERR_PROTO
        @test e.msg == "Protocol error"
    end
end

@testset "Invaid request" begin
    f1 = @async test_server()
    f2 = @async test_client(IOBuffer(), INVALID_REQUEST_HEADERS)

    fetch(f1)
    @test fetch(f2) == true
end
