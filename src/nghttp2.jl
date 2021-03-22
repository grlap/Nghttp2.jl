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
[ ] nghttp2_on_stream_close_callback, close stream on error
[ ] nghttp2_on_data_chunk_recv_callback 
    you should use nghttp2_on_frame_recv_callback to know all data frames are received. 
[ ]  #TODO here is a bug, NGHTTP2_DATA_FLAG_NO_END_STREAM only if trailer

03/15 
    simple http client works with enable push true, false
    does not send NGHTTP2_DATA_FLAG_NO_END_STREAM flag when sending request without trailer
"""

module Http2

export send, recv!, submit_request, request

using nghttp2_jll
using BitFlags
using DataStructures
using Sockets

const Option{T} = Union{Nothing, T} where {T}

@enum(Nghttp2Error,
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
    The category of HEADERS, which indicates the role of the frame.  In HTTP/2 spec,
    request, response, push response and other arbitrary headers (e.g., trailer fields)
    are all called just HEADERS. To give the application the role of incoming HEADERS frame,
    we define several categories.
"""
@enum(Nghttp2FrameHeadersCategory::UInt32,
    # The HEADERS frame is opening new stream, which is analogous to
    # SYN_STREAM in SPDY.
    NGHTTP2_HCAT_REQUEST = 0,
    # The HEADERS frame is the first response headers, which is analogous to SYN_REPLY in SPDY.
    NGHTTP2_HCAT_RESPONSE = 1,
    # The HEADERS frame is the first headers sent against reserved stream.
    NGHTTP2_HCAT_PUSH_RESPONSE = 2,
    # The HEADERS frame which does not apply for the above categories, which is analogous to
    # HEADERS in SPDY.  If non-final response (e.g., status 1xx) is used, final response HEADERS
    # frame will be categorized here.
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
    # Indicates that this name/value pair must not be indexed ("Literal Header Field never
    # Indexed" representation must be used in HPACK encoding).  Other implementation calls
    # this bit as "sensitive".
    NGHTTP2_NV_FLAG_NO_INDEX = 0x01,
    # This flag is set solely by application.  If this flag is set, the library does not make
    # a copy of header field name. This could improve performance.
    NGHTTP2_NV_FLAG_NO_COPY_NAME = 0x02,
    # This flag is set solely by application.  If this flag is set, the library does not make
    # a copy of header field value.  This could improve performance.
    NGHTTP2_NV_FLAG_NO_COPY_VALUE = 0x04)

"""
    The SETTINGS ID.
"""
@enum(Nghttp2SettingsId::UInt32,
    # SETTINGS_HEADER_TABLE_SIZE
    NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
    # SETTINGS_ENABLE_PUSH
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
    The flags used to set in data_flags output parameter in :type:`nghttp2_data_source_read_callback`.
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

const DefaultSettings =
    Vector{SettingsEntry}(
        [
            Http2.SettingsEntry(Http2.NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100),
            Http2.SettingsEntry(Http2.NGHTTP2_SETTINGS_ENABLE_PUSH, 1),
            Http2.SettingsEntry(Http2.NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 4*65536),
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
    Helper functionst to convert vector of string pairs to vector of NVPair.
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

struct Nghttp2Info
    age::Cint
    version_num::Cint
    version_str::Cstring
    proto_str::Cstring
end

"""
    Library definition.
"""
struct Stream
    stream_id::Int32
    buffer::IOBuffer
    headers::Dict{String, String}

    Stream(stream_id::Int32) = new(stream_id, IOBuffer(), Dict{String, String}())
end

mutable struct DataSource
    send_buffer::IOBuffer
    trailer::NVPairs
end

mutable struct DataProvider
    data_source::Ptr{DataSource}
    read_callback::Ptr{Cvoid}
end

"""
    Http2 session.
"""
mutable struct Session
    socket::TCPSocket
    nghttp2_session::Nghttp2Session
    session_id::Int64
    recv_streams::Dict{Int32, Stream}
    recv_streams_id::Queue{Int32}

    Session(socket::TCPSocket, session::Nghttp2Session, session_id::Int64) = new(socket, session, session_id, Dict{Int32, Stream}(), Queue{Int32}())
end

"""
    Established nghttp2 sessions.

    user_data::Ptr{Cvoid} to Session mapping.

    Allows to retrive Http2.Session in nghttp2 callbacks from nghttp2 session user data.
"""
const EstablishedSessions = Dict{Int64, Session}()
const EstablishedSessionsCond = Threads.Condition()
const SessionIdCounter = Threads.Atomic{Int64}(1)

"""
    Retrieves the session from the dictionary.
"""
function session_retrieve(user_data::Ptr{Cvoid})::Option{Session}
    session_id::Int64 = Int64(user_data)

    lock(EstablishedSessionsCond)
    try
        if (haskey(EstablishedSessions, session_id))
            session = EstablishedSessions[session_id]
            return session
        else
            return nothing
        end
    finally
        unlock(EstablishedSessionsCond)
    end
end

"""
    Stores the session in the dictionary.
"""
function session_store(session::Session)
    lock(EstablishedSessionsCond)
    try
        EstablishedSessions[session.session_id] = session
    finally
        unlock(EstablishedSessionsCond)
    end
end

"""
    Creates Nghttp2 options instance.
"""
function nghttp2_option_new()::Nghttp2Option
    nghttp2_option = Nghttp2Option(C_NULL)
    result = ccall((:nghttp2_option_new, libnghttp2), Cint, (Ref{Nghttp2Option},), nghttp2_option)
    if (result != 0)
        throw("error")
    end

    finalizer(nghttp2_option_del, nghttp2_option)
    return nghttp2_option
end

function nghttp2_option_del(nghttp2_option::Nghttp2Option)
    ccall((:nghttp2_option_del, libnghttp2), Cvoid, (Nghttp2Option,), nghttp2_option)
    nghttp2_option.ptr = C_NULL
end

"""
    Session callbacks.
"""
function nghttp2_session_callbacks_new()
    callbacks = Nghttp2SessionCallbacks(C_NULL)
    result = ccall((:nghttp2_session_callbacks_new, libnghttp2), Cint, (Ref{Nghttp2SessionCallbacks},), callbacks)
    if (result != 0)
        throw("error")
    end

    ccall((:nghttp2_session_callbacks_set_on_frame_recv_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_frame_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_recv_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_on_begin_headers_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_begin_headers_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_on_header_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_header_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_on_data_chunk_recv_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_data_chunk_recv_callback_ptr)

    ccall((:nghttp2_session_callbacks_set_send_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_send_callback_ptr);

    ccall((:nghttp2_session_callbacks_set_error_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_error_callback_ptr);

    ccall((:nghttp2_session_callbacks_set_on_stream_close_callback, libnghttp2),
        Cvoid,
        (Nghttp2SessionCallbacks, Ptr{Cvoid},),
        callbacks,
        on_stream_close_callback_ptr);

    finalizer(nghttp2_session_callbacks_del, callbacks)
    return callbacks
end

function nghttp2_session_callbacks_del(callbacks::Nghttp2SessionCallbacks)
    ccall((:nghttp2_session_callbacks_del, libnghttp2), Cvoid, (Nghttp2SessionCallbacks,), callbacks)
    callbacks.ptr = C_NULL
end

"""
    Server session.

    Creates a new server session and stores the session object in the lookup dictionary.
"""
function server_session_new(socket::TCPSocket)::Session
    session_id::Int64 = Threads.atomic_add!(SessionIdCounter, 1)

    nghttp2_session::Nghttp2Session = Nghttp2Session(C_NULL)

    callbacks = nghttp2_session_callbacks_new()

    result = ccall(
        (:nghttp2_session_server_new, libnghttp2),
        Cint,
        (Ref{Nghttp2Session}, Nghttp2SessionCallbacks, Ptr{Cvoid},),
        nghttp2_session,
        callbacks,
        Ptr{Cvoid}(session_id))

    session = Session(socket, nghttp2_session, session_id)
    session_store(session)

    return session
end

"""
    Client session.

    Creates a new client session.
"""
function client_session_new(socket::TCPSocket)::Session
    session_id::Int64 = Threads.atomic_add!(SessionIdCounter, 1)

    nghttp2_session::Nghttp2Session = Nghttp2Session(C_NULL)

    callbacks = nghttp2_session_callbacks_new()

    result = ccall(
        (:nghttp2_session_client_new, libnghttp2),
        Cint,
        (Ref{Nghttp2Session}, Nghttp2SessionCallbacks, Ptr{Cvoid},),
        nghttp2_session,
        callbacks,
        Ptr{Cvoid}(session_id))

    session = Session(socket, nghttp2_session, session_id)
    session_store(session)

    return session
end

function http2_session_del(session::Session)
    nghttp2_session_del(session.nghttp2_session)

    pop!(EstablishedSessions, session.session_id, nothing);
end

"""
    Session.
"""
function is_nghttp2_server_session(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_check_server_session, libnghttp2),
        Cint,
        (Nghttp2Session,),
        nghttp2_session)

    return result != 0
end

function nghttp2_session_del(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_del, libnghttp2), Cvoid, (Nghttp2Session,), session)
    nghttp2_session.ptr = C_NULL

    return result
end

function nghttp2_session_send(nghttp2_session::Nghttp2Session)
    result = ccall((:nghttp2_session_send, libnghttp2), Cint, (Nghttp2Session,), nghttp2_session)

    return result
end

function nghttp2_session_submit_settings(nghttp2_session::Nghttp2Session, settings::Vector{SettingsEntry})
    println("nghttp2_session_submit_settings $(settings)")
    result = ccall((:nghttp2_submit_settings, libnghttp2),
        Cint,
        (Nghttp2Session, UInt8, Ptr{Cvoid}, Csize_t),
        nghttp2_session,
        NGHTTP2_FLAG_NONE,
        pointer(settings),
        length(settings))

    println("nghttp2_session_submit_settings: $(result)")
    return result
end

function nghttp2_session_mem_recv(session::Nghttp2Session, input_data::Vector{UInt8})
    result = ccall((:nghttp2_session_mem_recv, libnghttp2),
        Cssize_t,
        (Nghttp2Session, Ptr{UInt8}, Csize_t,),
        session,
        input_data,
        length(input_data))

    return result
end

function nghttp2_session_recv(session::Nghttp2Session)
    result = ccall((:nghttp2_session_recv, libnghttp2), Cint, (Nghttp2Session,), session)
    return result
end

function nghttp2_submit_window_update(session::Nghttp2Session, stream_id::Int32, window_size_increment::Int32)
    result = ccall((:nghttp2_submit_window_update, libnghttp2), 
        Cint,
        (Nghttp2Session, UInt8, Cint, Cint),
        session,
        NGHTTP2_FLAG_NONE,
        stream_id,
        window_size_increment)

    println("nghttp2_submit_window_update $(stream_id) $(window_size_increment) $(result)")
    return result
end

"""
    Errors.
"""
nghttp2_error_to_string(error::Nghttp2Error) = unsafe_string(ccall((:nghttp2_strerror, libnghttp2), Cstring, (Cint,), error))

nghttp2_version() = unsafe_load(ccall((:nghttp2_version, libnghttp2), Ptr{Nghttp2Info}, (Cint,), 0))

Base.show(io::IO, info::Nghttp2Info) =
    println(
        io,
        """NGHttp2 lib: $(info.version_num)
        path: $(libnghttp2)
        version: $(unsafe_string(info.version_str))
        protocol: $(unsafe_string(info.proto_str))""")

Base.show(io::IO, frame_header::Nghttp2FrameHeader) =
    println(
        io,
        """Frame:
        length: $(frame_header.length)
        stream_id: $(frame_header.stream_id)
        type: $(Nghttp2FrameType(frame_header.type))
        flags: $(frame_header.flags)
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
    println("on_recv_callback")
    @show session
    @show buf
    @show len
    @show flags
    @show user_data

    # Get the server session object.
    session = session_retrieve(user_data)
    @show session

    result::Cssize_t = 0
    return result
end

function on_frame_recv_callback(nghttp2_session::Nghttp2Session, frame::Nghttp2Frame, user_data::Ptr{Cvoid})::Cint
    frame_header = unsafe_load(Ptr{Nghttp2FrameHeader}(frame.ptr))

    println("on_frame_recv_callback $(frame_header)")
    # https://nghttp2.org/documentation/types.html#c.nghttp2_on_frame_recv_callback

    result::Cint = 0
    return result
end

function on_begin_headers_callback(nghttp2_session::Nghttp2Session, frame::Nghttp2Frame, user_data::Ptr{Cvoid})::Cint
    # Get the server session object.
    session = session_retrieve(user_data)

    frame_header = unsafe_load(Ptr{Nghttp2FrameHeader}(frame.ptr))
    println("on_begin_headers_callback: $(Nghttp2FrameType(frame_header.type)) stream_id:$(frame_header.stream_id)")

    add_new_stream = false

    if (frame_header.type == UInt8(NGHTTP2_HEADERS))
        headers_frame = unsafe_load(Ptr{Nghttp2HeadersFrame}(frame.ptr))

        ## HERE is missing

        is_server::Bool = is_nghttp2_server_session(nghttp2_session)

        println(" $(is_server) $(headers_frame.cat) $((!is_server && headers_frame.cat == NGHTTP2_HCAT_RESPONSE))")
        if ((is_server && headers_frame.cat == NGHTTP2_HCAT_REQUEST) ||
            (!is_server && (headers_frame.cat == NGHTTP2_HCAT_RESPONSE || headers_frame.cat == NGHTTP2_HCAT_PUSH_RESPONSE)))
            add_new_stream = true
        end
    end

    if (frame_header.type == UInt8(NGHTTP2_PUSH_PROMISE))
        add_new_stream = true
    end

    if (add_new_stream)
        println(" adding new stream")
        # Create a new stream.
        session.recv_streams[frame_header.stream_id] = Stream(frame_header.stream_id)
    end

    result::Cint = 0
    return result
end

function on_header_recv_callback(nghttp2_session::Nghttp2Session, frame::Nghttp2Frame, name::Ptr{UInt8}, namelen::Csize_t, value::Ptr{UInt8}, valuelen::Csize_t, flags::UInt8, user_data::Ptr{Cvoid})::Cint
    # Get the server session object.
    session = session_retrieve(user_data)

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
    println("on_data_chunk_recv_callback stream_id:$(stream_id)")

    # Get the server session object.
    session = session_retrieve(user_data)

    # Copy from received buffer to the local data.
    data = Vector{UInt8}(undef, len)
    GC.@preserve data unsafe_copyto!(pointer(data), buf, len)

    # Write received data to the received stream buffer.
    recv_stream = session.recv_streams[stream_id]

    mark(recv_stream.buffer)
    write(recv_stream.buffer, data)
    reset(recv_stream.buffer)

    result::Cint = 0
    return result
end

function on_send_callback(nghttp2_session::Nghttp2Session, data::Ptr{UInt8}, length::Csize_t, flags::Cint, user_data::Ptr{Cvoid})::Csize_t
    # Get the server session object.
    session = session_retrieve(user_data)

    # Copy send data to the buffer.
    send_buf = Vector{UInt8}(undef, length)

    GC.@preserve send_buf unsafe_copyto!(pointer(send_buf), data, length)

    write(session.socket, send_buf)

    return length
end

function on_error_callback(nghttp2_session::Nghttp2Session, msg::Ptr{UInt8}, len::Csize_t, user_data::Ptr{Cvoid})
    println("on_error_callback")

    result::Cint = 0
    return result
end

function on_data_source_read_callback(nghttp2_session::Nghttp2Session, stream_id::Cint, buf::Ptr{UInt8}, buf_length::Csize_t, data_flags::Ptr{UInt32}, data_source::Ptr{Ptr{IOBuffer}}, user_data::Ptr{Cvoid})
    println("on_data_source_read_callback $(stream_id) $(buf):$(length) $(data_flags) $(data_source) $(user_data)")

    data_source = unsafe_load(data_source)
    data_source = unsafe_pointer_to_objref(data_source)

    data_buffer = read(data_source.send_buffer)

    GC.@preserve data_buffer unsafe_copyto!(buf, pointer(data_buffer), length(data_buffer))

    # #TODO here is a bug, NGHTTP2_DATA_FLAG_NO_END_STREAM only if trailer
    #unsafe_store!(data_flags, UInt32(NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM))
    unsafe_store!(data_flags, UInt32(NGHTTP2_DATA_FLAG_EOF))

    if length(data_source.trailer) != 0
        # Submit the trailer.
        #
        result = ccall((:nghttp2_submit_trailer, libnghttp2),
            Cint,
            (Nghttp2Session, Int32, Ptr{Cvoid}, Csize_t),
            nghttp2_session,
            stream_id,
            pointer(data_source.trailer),
            length(data_source.trailer))
    end

    result::Cssize_t = length(data_buffer)
    return result
end

function on_stream_close_callback(nghttp2_session::Nghttp2Session, stream_id::Cint, error_code::UInt32, user_data::Ptr{Cvoid})
    # Get the server session object.
    session = session_retrieve(user_data)

    println(">> on_stream_close_callback session:$(session.session_id) stream:$(stream_id)")

    # Stream was closed.
    enqueue!(session.recv_streams_id, stream_id)

    result::Cint = 0
    return result
end

const on_recv_callback_ptr = @cfunction on_recv_callback Cssize_t (Nghttp2Session, Ptr{UInt8}, Csize_t, Cint, Ptr{Cvoid})

const on_frame_recv_callback_ptr = @cfunction on_frame_recv_callback Cint (Nghttp2Session, Nghttp2Frame, Ptr{Cvoid})

const on_begin_headers_callback_ptr = @cfunction on_begin_headers_callback Cint (Nghttp2Session, Nghttp2Frame, Ptr{Cvoid})

const on_header_recv_callback_ptr = @cfunction on_header_recv_callback Cint (Nghttp2Session, Nghttp2Frame, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, UInt8, Ptr{Cvoid})

const on_data_chunk_recv_callback_ptr = @cfunction on_data_chunk_recv_callback Cint (Nghttp2Session, UInt8, Cint, Ptr{UInt8}, Csize_t, Ptr{Cvoid})

const on_send_callback_ptr = @cfunction on_send_callback Csize_t (Nghttp2Session, Ptr{UInt8}, Csize_t, Cint, Ptr{Cvoid})

const on_error_callback_ptr = @cfunction on_error_callback Cint (Nghttp2Session, Ptr{UInt8}, Csize_t, Ptr{Cvoid})

const on_data_source_read_callback_ptr = @cfunction on_data_source_read_callback Cssize_t (Nghttp2Session, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt32}, Ptr{Ptr{IOBuffer}}, Ptr{Cvoid})

const on_stream_close_callback_ptr = @cfunction on_stream_close_callback Cint (Nghttp2Session, Cint, UInt32, Ptr{Cvoid})

"""
    Http2 session.
"""

function submit_settings(session::Session, settings::Vector{SettingsEntry})
    result = nghttp2_session_submit_settings(session.nghttp2_session, settings)

    # result = nghttp2_session_send(session.nghttp2_session)

    return result
end

function submit_window_update(session::Session, stream_id::Int32, window_size_increment::Int32)
    result = nghttp2_submit_window_update(session.nghttp2_session, stream_id, window_size_increment)
    return result
end

function recv!(session::Session)
    while isempty(session.recv_streams_id) && !eof(session.socket)
        available_bytes = bytesavailable(session.socket)
        @show available_bytes

        input_data = read(session.socket, available_bytes)
        nghttp2_session_mem_recv(session.nghttp2_session, input_data)
    end

    if (isempty(session.recv_streams_id))
        return (0, Stream(Int32(0)))
    end

    # Return stream in the order they have been received.
    @show session.recv_streams_id
    recv_stream_id = dequeue!(session.recv_streams_id)
    println("Received a stream: $(recv_stream_id)")
    @show session.recv_streams_id

    @show recv_stream_id

    @show session.recv_streams

    recv_stream = pop!(session.recv_streams, recv_stream_id)

    return (recv_stream_id, recv_stream)
end

"""
    Send data to Http2 server session.
"""
function Sockets.send(session::Session, stream_id::Int32, send_buffer::IOBuffer, header::StringPairs = StringPairs(), trailer::StringPairs = StringPairs())
    println("send on $(session) $(stream_id)");

    headers::NVPairs = convert_to_nvpairs(header)
    trailers::NVPairs = convert_to_nvpairs(trailer)

    GC.@preserve send_buffer headers trailers begin

        data_source = DataSource(send_buffer, trailers)
        GC.@preserve data_source begin

            data_provider = DataProvider(pointer_from_objref(data_source), on_data_source_read_callback_ptr)
            GC.@preserve data_provider begin

                # headers and data
                #
                result = ccall((:nghttp2_submit_response, libnghttp2),
                    Cint,
                    (Nghttp2Session, Int32, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}),
                    session.nghttp2_session,
                    stream_id,
                    pointer(headers),
                    length(headers),
                    pointer_from_objref(data_provider))

                result = nghttp2_session_send(session.nghttp2_session)
            end
        end
    end

    # Release headers and trailers after sending the frame.
    finalize(headers)
    finalize(trailers)

    println("done sending:")
end

function submit_request(session::Session, send_buffer::IOBuffer, header::StringPairs = StringPairs(), trailer::StringPairs = StringPairs())
    println("submit_request")

    headers::NVPairs = convert_to_nvpairs(header)
    trailers::NVPairs = convert_to_nvpairs(trailer)

    GC.@preserve send_buffer headers trailers begin

        data_source = DataSource(send_buffer, trailers)
        GC.@preserve data_source begin

            data_provider = DataProvider(pointer_from_objref(data_source), on_data_source_read_callback_ptr)
            GC.@preserve data_provider begin

                # headers and data
                #
                stream_id = ccall((:nghttp2_submit_request, libnghttp2),
                    Cint,
                    (Nghttp2Session, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}),
                    session.nghttp2_session,
                    C_NULL,
                    pointer(headers),
                    length(headers),
                    pointer_from_objref(data_provider))
                if (stream_id < 0)
                    throw("error")
                end
                println("submitted request: $(stream_id)")

                result = nghttp2_session_send(session.nghttp2_session)
            end
        end
    end

    # Release headers and trailers after sending the frame.
    finalize(headers)
    finalize(trailers)

    println("done sending:")

    return stream_id
end

"""
    Public API.

    Wrapper classes around Http2.Session.
"""

struct ClientSession
    session::Session
end

function open(host::AbstractString, port::Integer)::ClientSession
    println("Open Http2Client: $(host):$(port)")
    socket = connect(host, port)
    @show socket

    session = client_session_new(socket)
    result =  submit_settings(session, DefaultSettings)
    result = submit_window_update(session, Int32(0), Int32(4*65536))

    client_session = ClientSession(session)
end

function request(client_session::ClientSession, header::StringPairs)
    println("request $(client_session) header:$(header)")

end

"""
    Runme.
"""

"""
    SERVER.
"""

const gRPC_Default_Status_200 = [":status" => "200", "content-type" => "application/grpc"]
const gRPC_Defautl_Trailer = ["grpc-status" => "0"]

const gRPC_Default_Request = [
    ":method" => "POST",
    ":path" => "/MlosAgent.ExperimentManagerService/Echo",
    ":authority" => "localhost:5000",
    ":scheme" => "http",
    "content-type" => "application/grpc",
    "user-agent" => "grpc-dotnet/2.29.0.0",
    "grpc-accept-encoding" => "identity,gzip"]

end # module Http2

using Sockets
using .Http2

function test_client()
    socket = connect("localhost", 5000)
    @show socket

    client_session = Http2.client_session_new(socket)

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

    cs = Http2.open("www.nghttp2.org", 80)

    iob = IOBuffer()
    @show stream_id1 = Http2.submit_request(
        cs.session, iob,
        [
            ":method" => "GET",
            ":path" => "/",
            ":scheme" => "http",
            ":authority" => "www.nghttp2.org",
            "user-agent" => "curl/7.75.0",
            "accept" => "*/*"
        ])
    
    @show recv_stream_id1, stream1 = Http2.recv!(cs.session)
    @show recv_stream_id2, stream2 = Http2.recv!(cs.session)

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

#    @show recv_stream_id3, stream3 = Http2.recv!(cs.session)
#    @show recv_stream_id4, stream4 = Http2.recv!(cs.session)
#    @show recv_stream_id5, stream5 = Http2.recv!(cs.session)
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

http_test()
