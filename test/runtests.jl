using Sockets
using OpenSSL
using Nghttp2
using Test

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
    stream_id1 = Nghttp2.submit_request(
        client_session.session,
        io,
        [
            ":method" => "GET",
            ":path" => "/",
            ":scheme" => "http",
            ":authority" => "www.nghttp2.org",
            "accept" => "*/*",
            "user-agent" => "curl/7.75.0"
        ])

    @test stream_id1 != 0

    recv_stream_id1, stream1 = Nghttp2.recv!(client_session.session)
    recv_stream_id2, stream2 = Nghttp2.recv!(client_session.session)

    println("=== [1]")
    #println("$(String(read(stream1.buffer)))")
    println("=== [2]")
    #println("$(String(read(stream2.buffer)))")
    # #TODO pinning is wrong, if removed it is crashing
    #@show recv_stream_id1, stream1
    #@show recv_stream_id2, stream2
end

@testset "Https2 Connection" begin
cs = connect("nghttp2.org", 443)

    ssl_ctx = OpenSSL.SSLContext(OpenSSL.TLSv12ClientMethod())
    result = OpenSSL.set_options(ssl_ctx, OpenSSL.SSL_OP_NO_COMPRESSION | OpenSSL.SSL_OP_NO_TLSv1_2)
    result = OpenSSL.set_alpn(ssl_ctx, OpenSSL.UPDATE_HTTP2_ALPN)

    bio_read_write = OpenSSL.BIO(cs)

    ssl = OpenSSL.SSL(ssl_ctx, bio_read_write, bio_read_write)
    @show result = OpenSSL.connect(ssl)
    @show OpenSSL.get_error()

    # Create SSL stream.
    ssl_stream = SSLStream(ssl)

    #socket = connect("www.nghttp2.org", 80)
    #@show socket

    cs = Nghttp2.open(ssl_stream)

    iob = IOBuffer()
    @show stream_id1 = Nghttp2.submit_request(
        cs.session, iob,
        [
            ":method" => "GET",
            ":path" => "/",
            ":scheme" => "https",
            ":authority" => "www.nghttp2.org",
            "accept" => "*/*",
            "user-agent" => "curl/7.75.0"
        ])

    recv_stream_id1, stream1 = Nghttp2.recv!(cs.session)
    recv_stream_id2, stream2 = Nghttp2.recv!(cs.session)

    println("=== [1]")
    println("$(String(read(stream1.buffer)))")
    println("=== [2]")
    println("$(String(read(stream2.buffer)))")
    # #TODO pinning is wrong, if removed it is crashing
    #@show recv_stream_id1, stream1
    #@show recv_stream_id2, stream2

    """
    @show stream_id2 = Http2.submit_request(
        cs.session, iob,
        [
            ":method" => "GET",
            ":path" => "/",
            ":scheme" => "http",
            ":authority" => "www.nghttp2.org",
            "user-agent" => "curl/7.75.0",
            "accept" => "text/html"
        ])

    @show recv_stream_id2, stream2 = Http2.recv!(cs.session)
    """
    # TODO hack, avoid gc cleanup
    ssl_ctx

#    @show recv_stream_id3, stream3 = Http2.recv!(cs.session)
#    @show recv_stream_id4, stream4 = Http2.recv!(cs.session)
#    @show recv_stream_id5, stream5 = Http2.recv!(cs.session)
end

function test_client()
    socket = connect("localhost", 5000)
    @show socket

    client_session = Nghttp2.client_session_new(socket)

    settings = Vector{Http2.SettingsEntry}([Http2.SettingsEntry(Http2.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100)])
    result = Http2.nghttp2_session_submit_settings(client_session.nghttp2_session, settings)

    data = UInt8[0x00, 0x00, 0x00, 0x00, 0x11, 0x0a, 0x0f, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x65, 0x65, 0x74, 0x65, 0x72, 0x20, 0x32]

    iob = IOBuffer(data)
    @show stream_id1 = submit_request(client_session, iob, Http2.gRPC_Default_Request, Http2.gRPC_Defautl_Trailer)

    iob = IOBuffer(data)
    @show stream_id2 = submit_request(client_session, iob, Http2.gRPC_Default_Request, Http2.gRPC_Defautl_Trailer)

    @show recv_stream_id1, stream1 = recv!(client_session)
    @show recv_stream_id2, stream2 = recv!(client_session)

    @show recv_buffer1 = IOBuffer(read(stream1.buffer))
    @show recv_buffer2 = IOBuffer(read(stream2.buffer))
end

function test_server()
    socket = listen(5000)
    accepted_socket = accept(socket)

    http2_session = Http2.server_session_new(accepted_socket)

    settings = Vector{Http2.SettingsEntry}([Http2.SettingsEntry(Http2.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100)])

    result = Http2.nghttp2_session_submit_settings(http2_session.nghttp2_session, settings)

    result = Http2.nghttp2_session_send(http2_session.nghttp2_session)

    while true
        stream_id, stream = recv!(http2_session)

        if (stream_id == 0)
            break
        end

        println("Received data from stream: $(stream_id)")
        @show stream.headers
        send_buffer = IOBuffer(read(stream.buffer))

        @show send_buffer

        send(http2_session,
            stream_id,
            send_buffer,
            Http2.gRPC_Default_Status_200,
            Http2.gRPC_Defautl_Trailer)
    end
end

function http_test()
    # /opt/homebrew/opt/curl/bin/curl --http2 --http2-prior-knowledge -i http://www.nghttp2.org


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

