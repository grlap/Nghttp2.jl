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

const DEFAULT_STATUS_200 = [":status" => "200"]
const DEFAULT_TRAILER = ["grpc-status" => "0"]

const DEFAULT_REQUEST_HEADERS = [":method" => "POST", ":path" => "/default", ":authority" => "localhost:5000", ":scheme" => "http", "content-type" => "application/text"]

const INVALID_REQUEST_HEADERS = [":method" => "POST", ":path" => "/default", ":scheme" => "http", "content-type" => "application/text", ":authority" => "localhost:5000"]

function test_server(socket::Sockets.TCPServer)
    accepted_socket = accept(socket)

    session_socket = Nghttp2.from_accepted(accepted_socket)

    local request_stream::Http2Stream

    try
        request_stream = recv(session_socket)
    catch ex
        close(session_socket)
        throw(ex)
    end

    println("==> test_server recv a stream")
    request_data = read_all(request_stream)
    println("test_server, received length: $(length(request_data))")

    send_buffer = IOBuffer(request_data)

    submit_response(request_stream, send_buffer, DEFAULT_STATUS_200)

    close(session_socket)

    return close(socket)
end

function test_server()
    socket = listen(5000)
    return test_server(socket)
end

function test_client(request_io::IO=IOBuffer(), headers=DEFAULT_REQUEST_HEADERS)
    tcp_connection = connect(5000)

    # Read all the input data to the buffer, use it later for comparision.
    request_data = read(request_io)
    request_iob = IOBuffer(request_data)

    client_session = Nghttp2.open(tcp_connection)

    stream1 = submit_request(client_session, request_iob, headers)
    response_data = read_all(stream1)

    @test length(response_data) == length(request_data)
    @test response_data == request_data

    return response_data == request_data
end
