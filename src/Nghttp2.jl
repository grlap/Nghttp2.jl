"""
    Nghttp2 Julia bindings.
"""

"""
    using Pkg
    Pkg.add("nghttp2_jll")
    Pkg.add("BitFlags")
    Pkg.add("DataStructures")

    # OpenSSL support
    Pkg.add("OpenSSL_jll")
    Pkg.add("MozillaCACerts_jll")

    include("Proto/ExperimentManagerService_pb.jl")
    include("nghttp2.jl")

    Items:
Nghttp2:
[x] add basic unit test, server, client
[ ] unit test to submit_response with payload > 16 KB
[ ] verify trailers are send at the end with request is send with multiple packages
[ ] figure out when to create a receive stream on receving a header 
[ ] submit_response should return a stream
[ ] add unit test with invalid response
[ ] Http2Stream return an error
[ ] nghttp2_on_stream_close_callback, close stream on error
[ ] nghttp2_on_data_chunk_recv_callback
    you should use nghttp2_on_frame_recv_callback to know all data frames are received
[ ] #TODO here is a bug, NGHTTP2_DATA_FLAG_NO_END_STREAM only if trailer
    does not send NGHTTP2_DATA_FLAG_NO_END_STREAM flag when sending request without trailer

[ ] Limit nghttp2_session_callbacks_set_data_source_read_length_callback
    max 64kb is allowed
    or try to nghttp2_submit_data


        session reading loop
            read and dispatch

            single Http2Session
                read()

            multiple entries from readstream
                until it is availabe

    Multiple Http2Streams are reading from a single Http2Session.

        ┌─────────────────┐
        │Http2Stream::read│─ ─ ─
        └─────────────────┘     │        session.read_lock
        ┌─────────────────┐      ─ ─ ▶    ╔════╗      ┌─────────────┐
        │Http2Stream::read│───────────────╣Lock╠─────▶│Session::read│
        └─────────────────┘      ─ ─ ▶    ╚════╝      └─────────────┘
        ┌─────────────────┐     │
        │Http2Stream::read│─ ─ ─
        └─────────────────┘

"""

module Nghttp2

export Http2ClientSession, Http2ServerSession, Http2Stream, Http2ProtocolException
export send, recv, try_recv, submit_request, submit_response, read, eof, bytesavailable, close
export nghttp2_version

using nghttp2_jll
using BitFlags
using DataStructures
using Sockets

const Option{T} = Union{Nothing, T} where {T}

"""
    Error codes used by Nghttp2 library.
"""
@enum(Nghttp2Error::Int32,
    NGHTTP2_ERR_INVALID_ARGUMENT = -501,
    NGHTTP2_ERR_BUFFER_ERROR = -502,
    NGHTTP2_ERR_UNSUPPORTED_VERSION = -503,
    NGHTTP2_ERR_WOULDBLOCK = -504,
    NGHTTP2_ERR_PROTO = -505,
    NGHTTP2_ERR_INVALID_FRAME = -506,
    NGHTTP2_ERR_EOF = -507,
    NGHTTP2_ERR_DEFERRED = -508,
    NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -509,
    NGHTTP2_ERR_STREAM_CLOSED = -510,
    NGHTTP2_ERR_STREAM_CLOSING = -511,
    NGHTTP2_ERR_STREAM_SHUT_WR = -512,
    NGHTTP2_ERR_INVALID_STREAM_ID = -513,
    NGHTTP2_ERR_INVALID_STREAM_STATE = -514,
    NGHTTP2_ERR_DEFERRED_DATA_EXIST = -515,
    NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -516,
    NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -517,
    NGHTTP2_ERR_INVALID_HEADER_BLOCK = -518,
    NGHTTP2_ERR_INVALID_STATE = -519,
    NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -521,
    NGHTTP2_ERR_FRAME_SIZE_ERROR = -522,
    NGHTTP2_ERR_HEADER_COMP = -523,
    NGHTTP2_ERR_FLOW_CONTROL = -524,
    NGHTTP2_ERR_INSUFF_BUFSIZE = -525,
    NGHTTP2_ERR_PAUSE = -526,
    NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -527,
    NGHTTP2_ERR_PUSH_DISABLED = -528,
    NGHTTP2_ERR_DATA_EXIST = -529,
    NGHTTP2_ERR_SESSION_CLOSING  = -530,
    NGHTTP2_ERR_HTTP_HEADER = -531,
    NGHTTP2_ERR_HTTP_MESSAGING = -532,
    NGHTTP2_ERR_REFUSED_STREAM = -533,
    NGHTTP2_ERR_INTERNAL = -534,
    NGHTTP2_ERR_CANCEL = -535,
    NGHTTP2_ERR_SETTINGS_EXPECTED = -536,
    NGHTTP2_ERR_TOO_MANY_SETTINGS = -537,
    NGHTTP2_ERR_FATAL = -900,
    NGHTTP2_ERR_NOMEM = -901,
    NGHTTP2_ERR_CALLBACK_FAILURE = -902,
    NGHTTP2_ERR_BAD_CLIENT_MAGIC = -903,
    NGHTTP2_ERR_FLOODED = -904)

"""
    The frame types in HTTP/2 specification.
"""
@enum(Nghttp2FrameType,
     # The DATA frame.
     NGHTTP2_DATA = 0,
     # The HEADERS frame.
     NGHTTP2_HEADERS = 0x01,
     # The PRIORITY frame.
     NGHTTP2_PRIORITY = 0x02,
     # The RST_STREAM frame.
     NGHTTP2_RST_STREAM = 0x03,
     # The SETTINGS frame.
     NGHTTP2_SETTINGS = 0x04,
     # The PUSH_PROMISE frame.
     NGHTTP2_PUSH_PROMISE = 0x05,
     # The PING frame.
     NGHTTP2_PING = 0x06,
     # The GOAWAY frame.
     NGHTTP2_GOAWAY = 0x07,
     # The WINDOW_UPDATE frame.
     NGHTTP2_WINDOW_UPDATE = 0x08,
     # The CONTINUATION frame.  This frame type won't be passed to any
     # callbacks because the library processes this frame type and its
     # preceding HEADERS/PUSH_PROMISE as a single frame.
     NGHTTP2_CONTINUATION = 0x09,
     # The ALTSVC frame, which is defined in `RFC 7383
     # <https://tools.ietf.org/html/rfc7838#section-4>`_.
     NGHTTP2_ALTSVC = 0x0a,
     # The ORIGIN frame, which is defined by `RFC 8336
     # <https://tools.ietf.org/html/rfc8336>`_.
     NGHTTP2_ORIGIN = 0x0c)

"""
    The category of HEADERS, which indicates the role of the frame.  In
    HTTP/2 spec, request, response, push response and other arbitrary
    headers (e.g., trailer fields) are all called just HEADERS.  To
    give the application the role of incoming HEADERS frame, we define
    several categories.
"""
@enum(Nghttp2FrameHeadersCategory::UInt32,
    # The HEADERS frame is opening new stream, which is analogous to
    # SYN_STREAM in SPDY.
    NGHTTP2_HCAT_REQUEST = 0,
    # The HEADERS frame is the first response headers, which is
    # analogous to SYN_REPLY in SPDY.
    NGHTTP2_HCAT_RESPONSE = 1,
    # The HEADERS frame is the first headers sent against reserved stream.
    NGHTTP2_HCAT_PUSH_RESPONSE = 2,
    # The HEADERS frame which does not apply for the above categories,
    # which is analogous to HEADERS in SPDY.  If non-final response
    # (e.g., status 1xx) is used, final response HEADERS frame will be
    # categorized here.
    NGHTTP2_HCAT_HEADERS = 3)

"""
    The flags for HTTP/2 frames.
    This enum defines all flags for all frames.
"""
@enum(Nghttp2FrameFlags::UInt8,
    # No flag set.
    NGHTTP2_FLAG_NONE = 0,
    # The END_STREAM flag.
    # The ACK flag.
    NGHTTP2_FLAG_END_STREAM = 0x01,
    # The END_HEADERS flag.
    NGHTTP2_FLAG_END_HEADERS = 0x04,
    # The PADDED flag.
    NGHTTP2_FLAG_PADDED = 0x08,
    # The PRIORITY flag.
    NGHTTP2_FLAG_PRIORITY = 0x20)

const NGHTTP2_FLAG_ACK = NGHTTP2_FLAG_END_STREAM

"""
    The flags for header field name/value pair.
"""
@enum(Nghttp2NvFlags::UInt8,
    # No flag set.
    NGHTTP2_NV_FLAG_NONE = 0,
    # Indicates that this name/value pair must not be indexed ("Literal
    # Header Field never Indexed" representation must be used in HPACK
    # encoding).  Other implementation calls this bit as "sensitive".
    NGHTTP2_NV_FLAG_NO_INDEX = 0x01,
    # This flag is set solely by application.  If this flag is set, the
    # library does not make a copy of header field name.  This could
    # improve performance.
    NGHTTP2_NV_FLAG_NO_COPY_NAME = 0x02,
    # This flag is set solely by application.  If this flag is set, the
    # library does not make a copy of header field value.  This could
    # improve performance.
    NGHTTP2_NV_FLAG_NO_COPY_VALUE = 0x04)

"""
    The SETTINGS ID.
"""
@enum(Nghttp2SettingsId::UInt32,
    # SETTINGS_HEADER_TABLE_SIZE
    NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
    # SETTINGS_ENABLE_PUSH, client only option.
    NGHTTP2_SETTINGS_ENABLE_PUSH = 0x02,
    # SETTINGS_MAX_CONCURRENT_STREAMS
    NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    # SETTINGS_INITIAL_WINDOW_SIZE
    NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
    # SETTINGS_MAX_FRAME_SIZE
    NGHTTP2_SETTINGS_MAX_FRAME_SIZE = 0x05,
    # SETTINGS_MAX_HEADER_LIST_SIZE
    NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06)

"""
    The flags used to set in |data_flags| output parameter in :type:`nghttp2_data_source_read_callback`.
"""
@bitflag Nghttp2DataFlags::UInt32 begin
    # No flag set.
    NGHTTP2_DATA_FLAG_NONE = 0
    # Indicates EOF was sensed.
    NGHTTP2_DATA_FLAG_EOF = 0x01
    # Indicates that END_STREAM flag must not be set even if
    # NGHTTP2_DATA_FLAG_EOF is set.  Usually this flag is used to send
    # trailer fields with `nghttp2_submit_request()` or
    # `nghttp2_submit_response()`.
    NGHTTP2_DATA_FLAG_NO_END_STREAM = 0x02
    # Indicates that application will send complete DATA frame in
    # :type:`nghttp2_send_data_callback`.
    NGHTTP2_DATA_FLAG_NO_COPY = 0x04
end

"""
    The SETTINGS ID/Value pair.
"""
struct SettingsEntry
    settings_id::Nghttp2SettingsId
    value::UInt32
end

const DEFAULT_SERVER_SETTINGS =
    Vector{SettingsEntry}(
        [
            SettingsEntry(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100),
        ])

const DEFAULT_CLIENT_SETTINGS =
    Vector{SettingsEntry}(
        [
            SettingsEntry(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100),
            SettingsEntry(NGHTTP2_SETTINGS_ENABLE_PUSH, 1),
        ])

"""
    The name/value pair, which mainly used to represent header fields.
    It creates a copy of the strings using malloc.
    String pointers can be safely passed to C function.
"""
struct NVPair
    name::Ptr{Cchar}
    value::Ptr{Cchar}
    namelen::Csize_t
    valuelen::Csize_t
    flags::UInt8

    NVPair(nothing) = new(C_NULL, C_NULL, 0, 0, UInt8(0))

    NVPair(nv_pair::Pair{String, String}) = NVPair(nv_pair.first, nv_pair.second, UInt8(0))

    function NVPair(name::String, value::String, flags::UInt8)
        name_len = length(name)
        value_len = length(value)

        # Reserve 2 bytes for the string terminator
        name_ptr = Ptr{UInt8}(Libc.calloc(name_len + value_len + 2, 1))

        value_ptr = name_ptr + name_len + 1

        GC.@preserve name unsafe_copyto!(name_ptr, pointer(name), name_len)
        GC.@preserve value unsafe_copyto!(value_ptr, pointer(value), value_len)

        nv_pair = new(name_ptr, value_ptr, name_len, value_len, flags)
    end
end

free(nv_pair::NVPair) = Libc.free(nv_pair.name)

"""
    Helper functions to convert vector of string pairs to vector of NVPair.
"""
const NVPairs = Vector{NVPair}

const StringPairs = Vector{Pair{String, String}}

function convert_to_nvpairs(input::StringPairs)
    nv_pairs = NVPairs()

    foreach(pair -> push!(nv_pairs, NVPair(pair)), input)

    finalizer(free, nv_pairs)

    return nv_pairs
end

free(nv_pairs::NVPairs) =
    for i in 1:length(nv_pairs)
        free(nv_pairs[i])
        nv_pairs[i] = NVPair(nothing)
    end

"""
    Nghttp2 library options.
"""
mutable struct Nghttp2Option
    ptr::Ptr{Cvoid}
end

mutable struct Nghttp2Session
    ptr::Ptr{Cvoid}
end

mutable struct Nghttp2SessionCallbacks
    ptr::Ptr{Cvoid}
end

mutable struct Nghttp2Frame
    ptr::Ptr{Cvoid}
end

"""
    The frame header.
"""
struct Nghttp2FrameHeader
    # The length field of this frame, excluding frame header.
    length::Csize_t
    # The stream identifier (aka, stream ID)
    stream_id::Int32
    # The type of this frame.  See `nghttp2_frame_type`.
    type::UInt8
    # The flags.
    flags::UInt8
    # Reserved bit in frame header.  Currently, this is always set to 0
    # and application should not expect something useful in here.
    reserved::UInt8
end

"""
    The structure to specify stream dependency.
"""
struct Nghttp2PrioritySpec
    # The stream ID of the stream to depend on.  Specifying 0 makes
    # stream not depend any other stream.
    stream_id::Int32
    #The weight of this dependency.
    weight::Int32
    # nonzero means exclusive dependency
    exclusive::UInt8
end

"""
    The HEADERS frame.
"""
struct Nghttp2HeadersFrame
    # The frame header.
    frame_header::Nghttp2FrameHeader
    # The length of the padding in this frame.  This includes PAD_HIGH and PAD_LOW.
    pad_len::Csize_t
    # The priority specification
    pri_spec::Nghttp2PrioritySpec
    # The name/value pairs.
    nva::Ptr{Cvoid}
    # The number of name/value pairs in |nva|.
    nvlen::Csize_t
    # The category of this HEADERS frame.
    cat::Nghttp2FrameHeadersCategory;
end

"""
    Nghttp2 library information.
"""
struct Nghttp2Info
    age::Cint
    version_num::Cint
    version_str::Cstring
    proto_str::Cstring
end

mutable struct DataSource
    send_stream::IOBuffer
    trailer::NVPairs
end

mutable struct DataProvider
    data_source::Ptr{DataSource}
    read_callback::Ptr{Cvoid}
end

"""
    Http2Exception
"""
mutable struct Http2ProtocolException <: Exception
    lib_error_code::Nghttp2Error
    msg::String

    Http2ProtocolException(lib_error_code::Nghttp2Error, msg::String) = new(lib_error_code, msg)

    function Http2ProtocolException(lib_error_code::Nghttp2Error)
        str_error = ccall((:nghttp2_strerror, libnghttp2),
            Cstring,
            (Nghttp2Error,),
            lib_error_code)

        return new(lib_error_code, unsafe_string(str_error))
    end
end

abstract type AbstractSession end

"""
    Library definition.
"""
mutable struct Http2Stream <: IO
    session::AbstractSession
    stream_id::Int32
    buffer::IOBuffer
    headers::Dict{String, String}
    lock::ReentrantLock
    eof::Bool

    Http2Stream(session::AbstractSession, stream_id::Int32) =
        new(session,
            stream_id,
            PipeBuffer(),
            Dict{String, String}(),
            ReentrantLock(),
            false)
end

"""
 Test whether an HTTP2 stream is at end-of-file.
"""
function Base.eof(http2_stream::Http2Stream)::Bool
    lock(http2_stream.lock) do
        return http2_stream.eof && eof(http2_stream.buffer)
    end
end

"""
    Return the number of bytes available for reading before a read from this stream will block.
"""
function Base.bytesavailable(http2_stream::Http2Stream)
    lock(http2_stream.lock) do
        return bytesavailable(http2_stream.buffer)
    end
end

function ensure_in_buffer(http2_stream::Http2Stream, nb::Integer)
    should_read = true

    # Process HTTP2 stack until there is no more available data in HTTP2 stream.
    while should_read
        lock(http2_stream.lock) do
            if bytesavailable(http2_stream.buffer) >= nb || http2_stream.eof
                should_read = false
            end
        end

        if should_read && internal_read!(http2_stream.session)
            continue
        end

        # Read failed
        break
    end

    # Throw exception is session is in error state.
    if has_error(http2_stream.session)
        throw(http2_stream.session.exception)
    end
end

"""
    Reads available data from the HTTP2 stream.
"""
function Base.read(http2_stream::Http2Stream)::Vector{UInt8}
    ensure_in_buffer(http2_stream, 1)

    lock(http2_stream.lock) do
        result_buffer = read(http2_stream.buffer)
        return result_buffer
    end
end

"""
    Reads at most nb bytes from from the HTTP2 stream.
"""
function Base.read(http2_stream::Http2Stream, nb::Integer)::Vector{UInt8}
    ensure_in_buffer(http2_stream, nb)

    lock(http2_stream.lock) do
        if bytesavailable(http2_stream.buffer) < nb
            throw(EOFError())
        end

        result_buffer = read(http2_stream.buffer, nb)
        return result_buffer
    end
end

function Base.read(http2_stream::Http2Stream, ::Type{UInt8})::UInt8
    return read(http2_stream, Core.sizeof(UInt8))[begin + 0]
end

function Base.unsafe_read(http2_stream::Http2Stream, p::Ptr{UInt8}, nb::UInt)
    ensure_in_buffer(http2_stream, nb)

    lock(http2_stream.lock) do
        if bytesavailable(http2_stream.buffer) < nb
            throw(EOFError())
        end

        result_buffer = read(http2_stream.buffer, nb)
        GC.@preserve result_buffer unsafe_copyto!(p, pointer(result_buffer), nb)
    end
end

"""
    Writes the data to the Http2 stream.
"""
function Base.write(http2_stream::Http2Stream, out_buffer::Vector{UInt8})
    # TODO handle errors
    lock(http2_stream.lock) do
        # Write the data to the steam.
        write(http2_stream.buffer, out_buffer)
    end
end

"""
    Internal HTTP2 session. Exposed as Http2ClientSession and Http2ServerSession.
"""
mutable struct Session <: AbstractSession
    io::IO
    nghttp2_session::Nghttp2Session
    session_id::Int64
    recv_streams::Dict{Int32, Http2Stream}
    recv_streams_id::Queue{Int32}
    exception::Option{Exception}
    lock::ReentrantLock
    read_lock::ReentrantLock

    Session(io::IO, nghttp2_session::Nghttp2Session) =
        new(io,
            nghttp2_session,
            Threads.atomic_add!(SessionIdCounter, 1),
            Dict{Int32, Http2Stream}(),
            Queue{Int32}(),
            nothing,
            ReentrantLock(),
            ReentrantLock())
end

const SessionIdCounter = Threads.Atomic{Int64}(1)

"""
    Retrieves the Session object from the nghttp2_session data.
    The Session object must be pinned.
"""
function session_from_data(user_data::Ptr{Cvoid})::Session
    session::Session = unsafe_pointer_to_objref(user_data)
    return session
end

"""
    Sets the session object in Nghttp2Session structure.
    The Session object must be pinned.
"""
function session_set_data(session::Session)
    ccall((:nghttp2_session_set_user_data, libnghttp2),
        Cvoid,
        (Nghttp2Session, Ptr{Cvoid},),
        session.nghttp2_session,
        pointer_from_objref(session))
end

"""
    Creates an instance of Nghttp2Options.
"""
function nghttp2_option_new()::Nghttp2Option
    nghttp2_option = Nghttp2Option(C_NULL)
    result = ccall((:nghttp2_option_new, libnghttp2),
        Cint,
        (Ref{Nghttp2Option},),
        nghttp2_option)
    if result != 0
        throw(Http2ProtocolException(Nghttp2Error(result)))
    end

    finalizer(nghttp2_option_del, nghttp2_option)
    return nghttp2_option
end

function nghttp2_option_del(nghttp2_option::Nghttp2Option)
    ccall((:nghttp2_option_del, libnghttp2),
        Cvoid,
        (Nghttp2Option,),
        nghttp2_option)
    nghttp2_option.ptr = C_NULL
end

function nghttp2_option_set_no_auto_window_update(nghttp2_option::Nghttp2Option, value::Cint)
    ccall((:nghttp2_option_set_no_auto_window_update, libnghttp2),
        Cvoid,
        (Nghttp2Option, Cint),
        nghttp2_option,
        value)
end

"""
    Session callbacks.
"""
function nghttp2_session_callbacks_new()
    callbacks = Nghttp2SessionCallbacks(C_NULL)
    result = ccall((:nghttp2_session_callbacks_new, libnghttp2),
        Cint,
        (Ref{Nghttp2SessionCallbacks},),
        callbacks)
    if (result != 0)
        throw(Http2ProtocolException(Nghttp2Error(result)))
    end

    ccall((:nghttp2_session_callbacks_set_on_frame_recv_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_frame_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_recv_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_on_begin_headers_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_begin_headers_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_on_header_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_header_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_on_data_chunk_recv_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_data_chunk_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_send_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_send_callback_ptr);

    ccall((:nghttp2_session_callbacks_set_error_callback2, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_error_callback_ptr);

    ccall((:nghttp2_session_callbacks_set_on_stream_close_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        NGHTTP2_CALLBACKS.x.on_stream_close_callback_ptr);

#    ccall((:nghttp2_session_callbacks_set_data_source_read_length_callback, libnghttp2),
#        Cvoid,
#        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
#        callbacks,
#        NGHTTP2_CALLBACKS.x.on_set_data_source_read_length_callback_ptr);

    finalizer(nghttp2_session_callbacks_del, callbacks)
    return callbacks
end

function nghttp2_session_callbacks_del(nghttp2_callbacks::Nghttp2SessionCallbacks)
    ccall((:nghttp2_session_callbacks_del, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks,), nghttp2_callbacks)
    nghttp2_callbacks.ptr = C_NULL
end

"""
    Server session.

    Creates a new server session and stores the session object in the lookup dictionary.
"""
function server_session_new(io::IO)::Session
    nghttp2_session::Nghttp2Session = Nghttp2Session(C_NULL)

    nghttp2_session_callbacks = nghttp2_session_callbacks_new()

    result = ccall((:nghttp2_session_server_new, libnghttp2),
        Cint,
        (Ref{Nghttp2Session}, Nghttp2SessionCallbacks, Ptr{Cvoid}),
        nghttp2_session,
        nghttp2_session_callbacks,
        C_NULL)
    if (result != 0)
        throw(Http2ProtocolException(Nghttp2Error(result)))
    end

    session = Session(io, nghttp2_session)

    nghttp2_session_callbacks_del(nghttp2_session_callbacks)

    return session
end

"""
    Client session.

    Creates a new client session.
"""
function client_session_new(io::IO)::Session
    nghttp2_session::Nghttp2Session = Nghttp2Session(C_NULL)

    nghttp2_session_callbacks = nghttp2_session_callbacks_new()

    result = ccall((:nghttp2_session_client_new, libnghttp2),
        Cint,
        (Ref{Nghttp2Session}, Nghttp2SessionCallbacks, Ptr{Cvoid},),
        nghttp2_session,
        nghttp2_session_callbacks,
        C_NULL)
    if (result != 0)
        throw(Http2ProtocolException(Nghttp2Error(result)))
    end

    session = Session(io, nghttp2_session)

    nghttp2_session_callbacks_del(nghttp2_session_callbacks)

    return session
end

"""
    Nghttp2Session.
"""
function is_nghttp2_server_session(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_check_server_session, libnghttp2),
        Cint,
        (Nghttp2Session,),
        nghttp2_session)

    return result != 0
end

function nghttp2_session_del(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_del, libnghttp2),
        Cvoid,
        (Nghttp2Session,),
        nghttp2_session)
    nghttp2_session.ptr = C_NULL

    return result
end

function nghttp2_session_terminate_session(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_terminate_session, libnghttp2),
        Cvoid,
        (Nghttp2Session,),
        nghttp2_session)

    return result
end

function nghttp2_submit_shutdown_notice(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_submit_shutdown_notice, libnghttp2),
        Cint,
        (Nghttp2Session,),
        nghttp2_session)

    return result
end

function nghttp2_session_send(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_send, libnghttp2),
        Cint,
        (Nghttp2Session,),
        nghttp2_session)

    return result
end

function nghttp2_session_submit_settings(nghttp2_session::Nghttp2Session, settings::Vector{SettingsEntry})
    result = ccall((:nghttp2_submit_settings, libnghttp2),
        Cint,
        (Nghttp2Session, UInt8, Ptr{Cvoid}, Csize_t),
        nghttp2_session,
        NGHTTP2_FLAG_NONE,
        pointer(settings),
        length(settings))

    return result
end

function nghttp2_session_mem_recv(nghttp2_session::Nghttp2Session, input_data::Vector{UInt8})
    result = ccall((:nghttp2_session_mem_recv, libnghttp2),
        Cssize_t,
        (Nghttp2Session, Ptr{UInt8}, Csize_t,),
        nghttp2_session,
        input_data,
        length(input_data))

    return result
end

function nghttp2_session_recv(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_recv, libnghttp2),
        Cint,
        (Nghttp2Session,),
        nghttp2_session)

    return result
end

function nghttp2_submit_window_update(
    nghttp2_session::Nghttp2Session,
    stream_id::Int32,
    window_size_increment::Int32)
    result = ccall((:nghttp2_submit_window_update, libnghttp2),
        Cint,
        (Nghttp2Session, UInt8, Cint, Cint),
        nghttp2_session,
        NGHTTP2_FLAG_NONE,
        stream_id,
        window_size_increment)

    return result
end

"""
    Errors.
"""
nghttp2_error_to_string(error::Nghttp2Error) = unsafe_string(ccall((:nghttp2_strerror, libnghttp2), Cstring, (Cint,), error))

nghttp2_version() = unsafe_load(ccall((:nghttp2_version, libnghttp2), Ptr{Nghttp2Info}, (Cint,), 0))

Base.show(io::IO, nghttp2_info::Nghttp2Info) =
    println(
        io,
        """NGHttp2 lib: $(nghttp2_info.version_num)
        path: $(libnghttp2)
        version: $(unsafe_string(nghttp2_info.version_str))
        protocol: $(unsafe_string(nghttp2_info.proto_str))""")

Base.show(io::IO, nghttp2_frame_header::Nghttp2FrameHeader) =
    println(
        io,
        """Frame:
        length: $(nghttp2_frame_header.length)
        stream_id: $(nghttp2_frame_header.stream_id)
        type: $(Nghttp2FrameType(nghttp2_frame_header.type))
        flags: $(nghttp2_frame_header.flags)
        """)

Base.show(io::IO, nv_pair::NVPair) =
    if (nv_pair.name == C_NULL)
        println(
            io,
            "NVPair: { nothing }")
    else
        println(
            io,
            "NVPair: { name: '$(unsafe_string(nv_pair.name)) $(nv_pair.name)', value: '$(unsafe_string(nv_pair.value)) $(nv_pair.value)' }")
    end

"""
    Callback implementation.
"""
function on_recv_callback(nghttp2_session::Nghttp2Session, buf::Ptr{UInt8}, len::Csize_t, flags::Cint, user_data::Ptr{Cvoid})::Cssize_t
    # Get the server session object.
    session = session_from_data(user_data)

    result::Cssize_t = 0
    return result
end

function on_frame_recv_callback(nghttp2_session::Nghttp2Session, frame::Nghttp2Frame, user_data::Ptr{Cvoid})::Cint
    # Get the server session object.
    session = session_from_data(user_data)

    frame_header = unsafe_load(Ptr{Nghttp2FrameHeader}(frame.ptr))

    stream_id = frame_header.stream_id
    last_frame = stream_id != 0 && frame_header.flags & UInt8(NGHTTP2_FLAG_END_STREAM) != 0

    if last_frame
        # Last frame in the stream detected, mark the stream as EOF.
        local http2_stream::Http2Stream

        lock(session.lock) do
            http2_stream = session.recv_streams[frame_header.stream_id]
        end

        lock(http2_stream.lock) do
            http2_stream.eof = true
        end
    end

    result::Cint = 0
    return result
end

function on_begin_headers_callback(nghttp2_session::Nghttp2Session, frame::Nghttp2Frame, user_data::Ptr{Cvoid})::Cint
    # Get the server session object.
    session = session_from_data(user_data)

    frame_header = unsafe_load(Ptr{Nghttp2FrameHeader}(frame.ptr))

    add_new_stream = false

    if (frame_header.type == UInt8(NGHTTP2_HEADERS))
        headers_frame = unsafe_load(Ptr{Nghttp2HeadersFrame}(frame.ptr))

        is_server::Bool = is_nghttp2_server_session(nghttp2_session)

        #TODO verify the logic to detect a new steam is correct
        #|| headers_frame.cat == NGHTTP2_HCAT_PUSH_RESPONSE
        #TODO rewrite this
        #TODO bug here we count incoming outgoing streams
        if ((is_server && headers_frame.cat == NGHTTP2_HCAT_REQUEST) ||
            (!is_server && (headers_frame.cat == NGHTTP2_HCAT_PUSH_RESPONSE || headers_frame.cat == Nghttp2.NGHTTP2_HCAT_RESPONSE)))
            add_new_stream = true
        end
    end

    if (frame_header.type == UInt8(NGHTTP2_PUSH_PROMISE))
        add_new_stream = true
    end

    # TODO workaround, how to detect when to add a new frame ??
    if (add_new_stream)
        # Create a new stream.
        lock(session.lock) do
            if !haskey(session.recv_streams, frame_header.stream_id)
                session.recv_streams[frame_header.stream_id] = Http2Stream(session, frame_header.stream_id)
                enqueue!(session.recv_streams_id, frame_header.stream_id)
            end
        end
    end

    result::Cint = 0
    return result
end

function on_header_recv_callback(nghttp2_session::Nghttp2Session, frame::Nghttp2Frame, name::Ptr{UInt8}, namelen::Csize_t, value::Ptr{UInt8}, valuelen::Csize_t, flags::UInt8, user_data::Ptr{Cvoid})::Cint
    # Get the server session object.
    session = session_from_data(user_data)

    frame_header = unsafe_load(Ptr{Nghttp2FrameHeader}(frame.ptr))

    # Copy from received buffer to the local data.
    header_name = Vector{UInt8}(undef, namelen)
    GC.@preserve header_name unsafe_copyto!(pointer(header_name), name, namelen)

    header_value = Vector{UInt8}(undef, valuelen)
    GC.@preserve header_value unsafe_copyto!(pointer(header_value), value, valuelen)

    # Store the header in the session stream.
    recv_stream = session.recv_streams[frame_header.stream_id]
    recv_stream.headers[String(header_name)] = String(header_value)

    result::Cint = 0
    return result
end

function on_data_chunk_recv_callback(nghttp2_session::Nghttp2Session, flags::UInt8, stream_id::Cint, buf::Ptr{UInt8}, len::Csize_t, user_data::Ptr{Cvoid})::Cint
    # Get the server session object.
    session = session_from_data(user_data)

    # Copy from received buffer to the local data.
    data = Vector{UInt8}(undef, len)
    GC.@preserve data unsafe_copyto!(pointer(data), buf, len)

    # Write received data to the received stream buffer.
    local http2_stream::Http2Stream

    lock(session.lock) do
        http2_stream = session.recv_streams[stream_id]
    end

    write(http2_stream, data)

    result::Cint = 0
    return result
end

function on_send_callback(nghttp2_session::Nghttp2Session, data::Ptr{UInt8}, length::Csize_t, flags::Cint, user_data::Ptr{Cvoid})::Csize_t
    # Get the server session object.
    session = session_from_data(user_data)

    # Copy send data to the buffer.
    out_buffer = Vector{UInt8}(undef, length)

    GC.@preserve out_buffer unsafe_copyto!(pointer(out_buffer), data, length)

    try
        write(session.io, out_buffer)
    catch ex
        lock(session.lock) do
            session.exception = ex
        end
        return Int(NGHTTP2_ERR_CALLBACK_FAILURE) % Csize_t
    end

    return length
end

function on_error_callback(
    nghttp2_session::Nghttp2Session,
    lib_error_code::Cint,
    msg::Ptr{UInt8},
    len::Csize_t,
    user_data::Ptr{Cvoid})::Cint
    session = session_from_data(user_data)
    println("on_error_callback session_id:$(session.session_id) nghtt2_error_code: $(lib_error_code)")

    # Create HTTP2 exception object, include Nghttp2 error.
    error = Http2ProtocolException(Nghttp2Error(lib_error_code), unsafe_string(msg))

    lock(session.lock) do
        session.exception = error
    end

    @show session.exception

    result::Cint = 0
    return result
end

function on_data_source_read_callback(
    nghttp2_session::Nghttp2Session,
    stream_id::Cint,
    buf::Ptr{UInt8},
    buf_length::Csize_t,
    data_flags::Ptr{UInt32},
    data_source::Ptr{Ptr{IOBuffer}},
    user_data::Ptr{Cvoid})::Cssize_t
    data_source = unsafe_load(data_source)
    data_source = unsafe_pointer_to_objref(data_source)

    in_buffer = read(data_source.send_stream, buf_length)
    in_length = length(in_buffer)

    GC.@preserve in_buffer unsafe_copyto!(buf, pointer(in_buffer), in_length)

    source_stream_eof = eof(data_source.send_stream)
    source_has_trailer = source_stream_eof && length(data_source.trailer) != 0

    send_data_flags::Nghttp2DataFlags = NGHTTP2_DATA_FLAG_NONE
    if source_stream_eof
        send_data_flags |= NGHTTP2_DATA_FLAG_EOF
    end

    if source_has_trailer
        send_data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM

        # Submit the trailer.
        result = ccall((:nghttp2_submit_trailer, libnghttp2),
            Cint,
            (Nghttp2Session, Int32, Ptr{Cvoid}, Csize_t),
            nghttp2_session,
            stream_id,
            pointer(data_source.trailer),
            length(data_source.trailer))
    end

    unsafe_store!(data_flags, UInt32(send_data_flags))

    result::Cssize_t = in_length
    return result
end

function on_stream_close_callback(
    nghttp2_session::Nghttp2Session,
    stream_id::Cint, 
    error_code::UInt32, 
    user_data::Ptr{Cvoid}):Cint
    # Get the server session object.
    session = session_from_data(user_data)

    result::Cint = 0
    return result
end

function on_set_data_source_read_length_callback(
    nghttp2_session::Nghttp2Session,
    frame_type::UInt8,
    stream_id::Cint,
    session_remote_window_size::Cint,
    stream_remote_window_size::Cint,
    remote_max_frame_size::UInt32,
    user_data::Ptr{Cvoid}):Cssize_t
    # Get the server session object.
    session = session_from_data(user_data)
    println("||=>on_set_data_source_read_length_callback")
    result::Cssize_t = 256*1024*1024
    return result
end

"""
    Nghttp2 callbacks.
"""
struct Nghttp2Callbacks
    on_recv_callback_ptr::Ptr{Nothing}
    on_frame_recv_callback_ptr::Ptr{Nothing}
    on_begin_headers_callback_ptr::Ptr{Nothing}
    on_header_recv_callback_ptr::Ptr{Nothing}
    on_data_chunk_recv_callback_ptr::Ptr{Nothing}
    on_send_callback_ptr::Ptr{Nothing}
    on_error_callback_ptr::Ptr{Nothing}
    on_data_source_read_callback_ptr::Ptr{Nothing}
    on_stream_close_callback_ptr::Ptr{Nothing}
    on_set_data_source_read_length_callback_ptr::Ptr{Nothing}

    function Nghttp2Callbacks()
        on_recv_callback_ptr = @cfunction on_recv_callback Cssize_t (Nghttp2Session, Ptr{UInt8}, Csize_t, Cint, Ptr{Cvoid})
        on_frame_recv_callback_ptr = @cfunction on_frame_recv_callback Cint (Nghttp2Session, Nghttp2Frame, Ptr{Cvoid})
        on_begin_headers_callback_ptr = @cfunction on_begin_headers_callback Cint (Nghttp2Session, Nghttp2Frame, Ptr{Cvoid})
        on_header_recv_callback_ptr = @cfunction on_header_recv_callback Cint (Nghttp2Session, Nghttp2Frame, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, UInt8, Ptr{Cvoid})
        on_data_chunk_recv_callback_ptr = @cfunction on_data_chunk_recv_callback Cint (Nghttp2Session, UInt8, Cint, Ptr{UInt8}, Csize_t, Ptr{Cvoid})
        on_send_callback_ptr = @cfunction on_send_callback Csize_t (Nghttp2Session, Ptr{UInt8}, Csize_t, Cint, Ptr{Cvoid})
        on_error_callback_ptr = @cfunction on_error_callback Cint (Nghttp2Session, Cint, Ptr{UInt8}, Csize_t, Ptr{Cvoid})
        on_data_source_read_callback_ptr = @cfunction on_data_source_read_callback Cssize_t (Nghttp2Session, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt32}, Ptr{Ptr{IOBuffer}}, Ptr{Cvoid})
        on_stream_close_callback_ptr = @cfunction on_stream_close_callback Cint (Nghttp2Session, Cint, UInt32, Ptr{Cvoid})
        on_set_data_source_read_length_callback_ptr = @cfunction on_set_data_source_read_length_callback Cssize_t (Nghttp2Session, UInt8, Cint, Cint, Cint, UInt32, Ptr{Cvoid})

        return new(
            on_recv_callback_ptr,
            on_frame_recv_callback_ptr,
            on_begin_headers_callback_ptr,
            on_header_recv_callback_ptr,
            on_data_chunk_recv_callback_ptr,
            on_send_callback_ptr,
            on_error_callback_ptr,
            on_data_source_read_callback_ptr,
            on_stream_close_callback_ptr,
            on_set_data_source_read_length_callback_ptr)
    end
end

"""
    HTTP2 session.
"""
function submit_settings(session::Session, settings::Vector{SettingsEntry})
    GC.@preserve session begin
        session_set_data(session)

        result = nghttp2_session_submit_settings(session.nghttp2_session, settings)
        if result != 0
            throw(Http2ProtocolException(Nghttp2Error(result)))
        end

        result = nghttp2_session_send(session.nghttp2_session)
        if result != 0
            throw(Http2ProtocolException(Nghttp2Error(result)))
        end
    end
end

"""
    Returns true, if session is in error state.
"""
function has_error(session::Session)
    lock(session.lock) do
        return !isnothing(session.exception)
    end
end

function set_error(session::Session, http2_protocol_exception::Http2ProtocolException)
    lock(session.lock) do
        if !isnothing(session.exception)
            session.exception = http2_protocol_exception
        end
    end
end

"""
    Reads from the session input IO and sends it to HTTP2 stack.
    Returns true if there is more data available.
    Ensure only one task is reading from the session.
"""
function internal_read!(session::Session)::Bool
    # Return if there are errors.
    if has_error(session)
        return false
    end

    lock(session.read_lock) do
        if bytesavailable(session.io) != 0 || !eof(session.io)
            available_bytes = bytesavailable(session.io)
            input_data = read(session.io, available_bytes)

            GC.@preserve session begin
                session_set_data(session)

                result = nghttp2_session_mem_recv(session.nghttp2_session, input_data)
                if result < 0
                    set_error(session, Http2ProtocolException(Nghttp2Error(result)))
                end

                result = nghttp2_session_send(session.nghttp2_session)
                if result < 0
                    set_error(session, Http2ProtocolException(Nghttp2Error(result)))
                end
            end

            return true
        end
    end

    return false
end

"""
    Receive from the session.
"""
function Sockets.recv(session::Session)::Option{Http2Stream}
    is_reading = true

    while is_reading
        lock(session.lock) do
            # Throw exception if errors occurred.
            if !isnothing(session.exception)
                throw(session.exception)
            end

            # Break, if there is no data available in the session's IO and
            # there are no more HTTP2 streams to return.
            if !isempty(session.recv_streams_id) || eof(session.io)
                is_reading = false
            end
        end

        if is_reading
            # Process received data through the HTTP2 stack.
            internal_read!(session)
            continue
        end

        break
    end

    lock(session.lock) do
        # If available, return a new HTTP2 stream.
        if !isempty(session.recv_streams_id)
            recv_stream_id = dequeue!(session.recv_streams_id)
            recv_stream = session.recv_streams[recv_stream_id]

            return recv_stream
        end

        if eof(session.io)
            return nothing
        end
    end
end

"""
    Returns available Http2Streams.
    If there are no active Http2Streams, returns nothing.
"""
function try_recv(session::Session)::Option{Http2Stream}
    lock(session.lock) do
        # Throw exception if errors occurred.
        if !isnothing(session.exception)
            throw(session.exception)
        end

        # If available, return Http2Stream.
        if !isempty(session.recv_streams_id)
            recv_stream_id = dequeue!(session.recv_streams_id)
            recv_stream = session.recv_streams[recv_stream_id]

            return recv_stream
        end

        return nothing
    end
end

"""
    Sends the data in IO stream via HTTP2 session.
"""
function send(
    session::Session,
    stream_id::Int32,
    send_buffer::IO,
    header::StringPairs = StringPairs(),
    trailer::StringPairs = StringPairs())

    headers::NVPairs = convert_to_nvpairs(header)
    trailers::NVPairs = convert_to_nvpairs(trailer)

    GC.@preserve session send_buffer headers trailers begin
        session_set_data(session)

        data_source = DataSource(send_buffer, trailers)

        GC.@preserve data_source begin
            data_provider = DataProvider(
                pointer_from_objref(data_source),
                NGHTTP2_CALLBACKS.x.on_data_source_read_callback_ptr)

            GC.@preserve data_provider begin
                # send headers, data, and trailers
                result = ccall((:nghttp2_submit_response, libnghttp2),
                    Cint,
                    (Nghttp2Session, Int32, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}),
                    session.nghttp2_session,
                    stream_id,
                    pointer(headers),
                    length(headers),
                    pointer_from_objref(data_provider))
                if result < 0
                    set_error(session, Http2ProtocolException(Nghttp2Error(result)))
                end

                result = nghttp2_session_send(session.nghttp2_session)
                if result < 0
                    set_error(session, Http2ProtocolException(Nghttp2Error(result)))
                end

                while !eof(send_buffer) && !has_error(session)
                    internal_read!(session)
                end
            end
        end
    end

    # Release headers and trailers after sending the frame.
    finalize(headers)
    finalize(trailers)

    # Throw exception if errors occurred.
    if has_error(session)
        throw(session.exception)
    end
end

function send(
    session::Session,
    send_buffer::IOBuffer,
    header::StringPairs = StringPairs(),
    trailer::StringPairs = StringPairs())

    headers::NVPairs = convert_to_nvpairs(header)
    trailers::NVPairs = convert_to_nvpairs(trailer)

    GC.@preserve session send_buffer headers trailers begin
        session_set_data(session)

        data_source = DataSource(send_buffer, trailers)

        GC.@preserve data_source begin
            data_provider = DataProvider(
                pointer_from_objref(data_source),
                NGHTTP2_CALLBACKS.x.on_data_source_read_callback_ptr)

            GC.@preserve data_provider begin
                # send headers, data, and trailers
                stream_id = ccall((:nghttp2_submit_request, libnghttp2),
                    Cint,
                    (Nghttp2Session, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}),
                    session.nghttp2_session,
                    C_NULL,
                    pointer(headers),
                    length(headers),
                    pointer_from_objref(data_provider))
                if stream_id < 0
                    throw(Http2ProtocolException(Nghttp2Error(stream_id)))
                end

                result = nghttp2_session_send(session.nghttp2_session)
                if result < 0
                    set_error(session, Http2ProtocolException(Nghttp2Error(result)))
                end

                while !eof(send_buffer) && !has_error(session)
                    internal_read!(session)
                end
            end
        end
    end

    # Release headers and trailers after sending the frame.
    finalize(headers)
    finalize(trailers)

    # Throw exception if errors occurred.
    if has_error(session)
        throw(session.exception)
    end

    return stream_id
end

"""
    Public API.

    Wrapper classes around Http2Session.
"""

"""
    Http2 client session.
"""
struct Http2ClientSession
    session::Session
end

function open(io::IO)::Http2ClientSession
    session = client_session_new(io)
    result =  submit_settings(session, DEFAULT_CLIENT_SETTINGS)

    return Http2ClientSession(session)
end

function submit_request(
    http2_client_session::Http2ClientSession,
    io::IO,
    header::StringPairs = StringPairs(),
    trailer::StringPairs = StringPairs())

    return send(
        http2_client_session.session,
        io,
        header,
        trailer)
end

"""
    Http2 server session.
"""
struct Http2ServerSession
    session::Session
end

function from_accepted(io::IO)::Http2ServerSession
    session = server_session_new(io)
    result = submit_settings(session, DEFAULT_SERVER_SETTINGS)

    return Http2ServerSession(session)
end

function Sockets.recv(http2_server_session::Http2ServerSession)
    return recv(http2_server_session.session)
end

function Base.close(http2_server_session::Http2ServerSession)
    println("Close http2_server_session")
    result = nghttp2_submit_shutdown_notice(http2_server_session.session.nghttp2_session)
    if result != 0
        throw(Http2ProtocolException(Nghttp2Error(result)))
    end

    result = nghttp2_session_send(http2_server_session.session.nghttp2_session)
    if result != 0
        throw(Http2ProtocolException(Nghttp2Error(result)))
    end

    close(http2_server_session.session.io)
end

"""
    Http2 stream.
"""
function submit_response(
    http2_stream::Http2Stream,
    io::IO,
    header::StringPairs = StringPairs(),
    trailer::StringPairs = StringPairs())

    session = http2_stream.session
    stream_id = http2_stream.stream_id

    return send(
        session,
        stream_id,
        io,
        header,
        trailer)
end

"""
    Runme.
"""

const NGHTTP2_CALLBACKS = Ref{Nghttp2Callbacks}()

"""
    Initialize the module.
"""
function __init__()
    println("$(@__MODULE__)::__init")
    NGHTTP2_CALLBACKS.x = Nghttp2Callbacks()
end

end # module Nghttp2
