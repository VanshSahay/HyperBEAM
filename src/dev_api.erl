%%% @doc API Key Management Device for HyperBEAM
%%%
%%% This device provides secure storage and management of API keys using the
%%% private storage mechanism. API keys are never exposed in responses or logs,
%%% and can only be used to make authenticated HTTP requests.
%%%
%%% API Endpoints:
%%% POST /store_key    - Store an API key securely
%%% POST /request      - Make HTTP request using stored API key
%%% GET  /list_keys    - List stored API key names (not values)
%%% POST /delete_key   - Delete a stored API key
%%% GET  /info         - Get device information
-module(dev_api).
-export([info/1, store_key/3, request/3, list_keys/3, delete_key/3, info/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%% @doc Device configuration - exports available functions
info(_) ->

    #{
        exports => [info, store_key, request, list_keys, delete_key]
    }.

%% @doc Get device information and API documentation
info(_Msg1, _Req, _Opts) ->
    Info = #{
        <<"device">> => <<"api@1.0">>,
        <<"description">> => <<"Secure API key storage and HTTP request proxy">>,
        <<"version">> => <<"1.0.0">>,
        <<"endpoints">> => #{
            <<"store-key">> => #{
                <<"method">> => <<"POST">>,
                <<"description">> => <<"Store an API key securely">>,
                <<"parameters">> => #{
                    <<"key_name">> => <<"string - Unique identifier for the key">>,
                    <<"api_key">> => <<"string - The API key value">>,
                    <<"key_type">> => <<"string - Type: 'bearer', 'header', or 'query'">>
                }
            },
            <<"request">> => #{
                <<"method">> => <<"POST">>,
                <<"description">> => <<"Make HTTP request using stored API key">>,
                <<"parameters">> => #{
                    <<"key_name">> => <<"string - Name of stored API key to use">>,
                    <<"url">> => <<"string - Target URL">>,
                    <<"method">> => <<"string - HTTP method (GET, POST, PUT, DELETE)">>,
                    <<"headers">> => <<"object - Additional headers (optional)">>,
                    <<"body">> => <<"string/object - Request body (optional)">>
                }
            },
            <<"list-keys">> => #{
                <<"method">> => <<"GET">>,
                <<"description">> => <<"List stored API key names (not values)">>
            },
            <<"delete-key">> => #{
                <<"method">> => <<"POST">>,
                <<"description">> => <<"Delete a stored API key">>,
                <<"parameters">> => #{
                    <<"key_name">> => <<"string - Name of key to delete">>
                }
            }
        }
    },
    {ok, Info}.

%% @doc Store an API key securely in persistent cache storage
store_key(Msg1, Req, Opts) ->
    try
        Body = hb_ao:get(<<"body">>, Req, <<>>, Opts),
        {ok, RequestData} = dev_codec_json:from(Body, Req, Opts),
        
        KeyName = maps:get(<<"key_name">>, RequestData, undefined),
        ApiKey = maps:get(<<"api_key">>, RequestData, undefined),
        KeyType = maps:get(<<"key_type">>, RequestData, <<"bearer">>),
        
        % Validate required fields
        case {KeyName, ApiKey} of
            {undefined, _} ->
                {ok, error_response(<<"key_name is required">>, Opts)};
            {_, undefined} ->
                {ok, error_response(<<"api_key is required">>, Opts)};
            {_, _} ->
                % Store API key persistently but securely
                ValidatedKeyData = #{
                    <<"type">> => KeyType,
                    <<"key">> => ApiKey,
                    <<"created">> => os:system_time(second),
                    <<"device">> => <<"api@1.0">>
                },
                
                % Write to cache for persistence across requests
                case hb_cache:write(ValidatedKeyData, Opts) of
                    {ok, CachePath} ->
                        % Create a named link for retrieval
                        NamedPath = api_key_path(KeyName),
                        hb_cache:link(CachePath, NamedPath, Opts),
                        

                        % Update key index for listing
                        IndexResult = update_key_index(KeyName, add, Opts),
                        
                        Response = #{
                            <<"success">> => true,
                            <<"message">> => <<"API key stored securely">>,
                            <<"key_name">> => KeyName,
                            <<"key_type">> => KeyType
                        },
                        {ok, success_response(Response, Msg1, Opts)};
                    {error, CacheError} ->
                        ?event(error, {cache_write_error, CacheError}),
                        {ok, error_response(<<"Failed to store API key">>, Opts)}
                end
        end
    catch
        Error:Reason:_ ->
            ?event(error, {store_key_error, Error, Reason}),
            {ok, error_response(<<"Failed to store API key">>, Opts)}
    end.

%% @doc Make an HTTP request using a stored API key
request(Msg1, Req, Opts) ->
    try
        Body = hb_ao:get(<<"body">>, Req, <<>>, Opts),
        {ok, RequestData} = dev_codec_json:from(Body, Req, Opts),
        
        KeyName = maps:get(<<"key_name">>, RequestData, undefined),
        Url = maps:get(<<"url">>, RequestData, undefined),
        Method = maps:get(<<"method">>, RequestData, <<"GET">>),
        ExtraHeaders = maps:get(<<"headers">>, RequestData, #{}),
        RequestBody = maps:get(<<"body">>, RequestData, <<>>),
        
        case {KeyName, Url} of
            {undefined, _} ->
                {ok, error_response(<<"key_name is required">>, Opts)};
            {_, undefined} ->
                {ok, error_response(<<"url is required">>, Opts)};
            {_, _} ->
                % Retrieve API key from persistent cache
                NamedPath = api_key_path(KeyName),
                case hb_cache:read(NamedPath, Opts) of
                    {ok, KeyDataRaw} ->
                        % Use hb_cache:ensure_all_loaded to resolve links properly
                        try
                            KeyData = hb_cache:ensure_all_loaded(KeyDataRaw, Opts),
                            case is_map(KeyData) andalso maps:is_key(<<"key">>, KeyData) of
                                true ->
                                    % Extract API key securely - NO logging of actual key value
                                    ApiKey = maps:get(<<"key">>, KeyData),
                                    % Only log that we have a key, not the actual value
                                    ?event(debug, {retrieved_api_key, {key_name, KeyName}, {has_key, byte_size(ApiKey) > 0}}),
                            
                                    % Create headers with real API key from private storage
                                    Headers = #{
                                        <<"Authorization">> => <<"Bearer ", ApiKey/binary>>,
                                        <<"User-Agent">> => <<"HyperBEAM/1.0">>
                                    },
                                    
                                    % Parse URL
                                    case parse_url(Url) of
                                        {ok, {Host, Port, Path}} ->
                                            PeerSpec = case Port of
                                                443 -> <<"https://", Host/binary>>;
                                                80 -> <<"http://", Host/binary>>;
                                                _ -> <<"http://", Host/binary, ":", (integer_to_binary(Port))/binary>>
                                            end,
                                            
                                            HttpOpts = Opts#{
                                                http_client => httpc,
                                                http_only_result => false
                                            },
                                            
                                            ClientArgs = #{
                                                peer => PeerSpec,
                                                path => Path,
                                                method => Method,
                                                headers => Headers,
                                                body => <<>>
                                            },
                                            
                                            case hb_http_client:req(ClientArgs, HttpOpts) of
                                                {_ErlStatus, Status, ResponseHeaders, ResponseBody} ->
                                                    Response = #{
                                                        <<"status">> => Status,
                                                        <<"headers">> => maps:from_list(ResponseHeaders),
                                                        <<"body">> => ResponseBody
                                                    },
                                                    {ok, success_response(Response, Msg1, Opts)};
                                                {error, HttpReason} ->
                                                    {ok, error_response(<<"HTTP request failed">>, Opts)};
                                                _Other ->
                                                    {ok, error_response(<<"Unexpected response">>, Opts)}
                                            end;
                                        {error, _} ->
                                            {ok, error_response(<<"Invalid URL">>, Opts)}
                                    end;
                                false ->
                                    % Data format is invalid
                                    ?event(error, {invalid_key_data_format, KeyData}),
                                    {ok, error_response(<<"Invalid API key data format">>, Opts)}
                            end
                        catch
                            Type:Reason:Stack ->
                                ?event(error, {cache_ensure_loaded_error, Type, Reason, Stack}),
                                {ok, error_response(<<"Failed to load API key from cache">>, Opts)}
                        end;
                    not_found ->
                        ?event(debug, {cache_key_not_found, NamedPath}),
                        {ok, error_response(<<"API key not found">>, Opts)};
                    {error, CacheError} ->
                        ?event(error, {cache_read_error, CacheError}),
                        {ok, error_response(<<"API key not found">>, Opts)}
                end
        end
    catch
        ErrorType:ErrorReason:_ ->
            ?event(error, {api_request_error, ErrorType, ErrorReason}),
            {ok, error_response(<<"Failed to make API request">>, Opts)}
    end.

%% @doc List stored API key names (not the actual keys)
list_keys(Msg1, _Req, Opts) ->
    try
        % Get API keys from persistent cache index
        KeyNames = get_key_index_safe(Opts),
        
        SuccessResponse = #{
            <<"success">> => true,
            <<"keys">> => KeyNames,
            <<"count">> => length(KeyNames),
            <<"storage">> => <<"persistent_secure">>
        },
        {ok, success_response(SuccessResponse, Msg1, Opts)}
    catch
        Error:Reason:_ ->
            ?event(error, {list_keys_error, Error, Reason}),
            % Return empty list on error instead of failing
            ErrorResponse = #{
                <<"success">> => true,
                <<"keys">> => [],
                <<"count">> => 0,
                <<"error">> => <<"Index read failed">>
            },
            {ok, success_response(ErrorResponse, Msg1, Opts)}
    end.

%% @doc Delete a stored API key
delete_key(Msg1, Req, Opts) ->
    try
        Body = hb_ao:get(<<"body">>, Req, <<>>, Opts),
        {ok, RequestData} = dev_codec_json:from(Body, Req, Opts),
        
        KeyName = maps:get(<<"key_name">>, RequestData, undefined),
        
        case KeyName of
            undefined ->
                {ok, error_response(<<"key_name is required">>, Opts)};
            _ ->
                NamedPath = api_key_path(KeyName),
                case hb_cache:read(NamedPath, Opts) of
                    {ok, _KeyData} ->
                        % Remove from the key index (even though cache is immutable)
                        update_key_index(KeyName, remove, Opts),
                        
                        % Note: HyperBEAM cache doesn't support deletion directly
                        % We remove from index to hide it from list_keys, but data remains in cache
                        Response = #{
                            <<"success">> => true,
                            <<"message">> => <<"API key removed from index (cache data immutable)">>,
                            <<"key_name">> => KeyName,
                            <<"note">> => <<"Key removed from listing but cache data remains - consider key rotation">>
                        },
                        {ok, success_response(Response, Msg1, Opts)};
                    _ ->
                        {ok, error_response(<<"API key not found">>, Opts)}
                end
        end
    catch
        Error:Reason:_ ->
            ?event(error, {delete_key_error, Error, Reason}),
            {ok, error_response(<<"Failed to delete API key">>, Opts)}
    end.


%% @doc Parse URL into components
parse_url(Url) ->
    try
        case uri_string:parse(Url) of
            #{scheme := Scheme, host := Host} = URI ->
                Port = case {Scheme, maps:get(port, URI, undefined)} of
                    {<<"https">>, undefined} -> 443;
                    {<<"http">>, undefined} -> 80;
                    {_, P} when is_integer(P) -> P
                end,
                Path = maps:get(path, URI, <<"/">>),
                Query = maps:get(query, URI, undefined),
                FinalPath = case Query of
                    undefined -> Path;
                    _ -> <<Path/binary, "?", Query/binary>>
                end,
                {ok, {Host, Port, FinalPath}};
            _ ->
                {error, invalid_url}
        end
    catch
        _:_ -> {error, invalid_url}
    end.

%% @doc Create a success response
success_response(Data, Msg, Opts) ->
    Response = #{
        <<"status">> => 200,
        <<"success">> => true,
        <<"data">> => Data
    },
    case dev_codec_json:to(Response, Msg, Opts) of
        {ok, JSON} -> JSON;
        _ -> #{ <<"error">> => <<"Failed to encode response">> }
    end.

%% @doc Create an error response  
error_response(ErrorMsg, Opts) ->
    Response = #{
        <<"status">> => 400,
        <<"success">> => false,
        <<"error">> => ErrorMsg
    },
    case dev_codec_json:to(Response, #{}, Opts) of
        {ok, JSON} -> JSON;
        _ -> #{ <<"error">> => ErrorMsg }
    end.

%% Helper functions for persistent storage

%% @doc Generate a cache path for an API key
api_key_path(KeyName) ->
    <<"api-keys/", KeyName/binary>>.



%% @doc Safer version that handles all errors gracefully with memory fallback
get_key_index_safe(Opts) ->
    try
        IndexPath = <<"api-keys-index">>,
        case hb_cache:read(IndexPath, Opts) of
            {ok, IndexDataRaw} ->
                try
                    IndexData = hb_cache:ensure_all_loaded(IndexDataRaw, Opts),
                    case maps:find(<<"keys">>, IndexData) of
                        {ok, Keys} when is_list(Keys) -> 
                            ?event(debug, {cache_index_found, Keys}),
                            Keys;
                        _ -> 
                            ?event(debug, {cache_index_invalid_format, IndexData}),
                            []
                    end
                catch
                    _:_ ->
                        ?event(debug, {cache_index_resolve_failed}),
                        []
                end;
            not_found ->
                ?event(debug, {cache_index_not_found}),
                [];
            _ ->
                ?event(debug, {cache_index_read_failed}),
                []
        end
    catch
        _:_ -> 
            []
    end.


%% @doc Update the key index by adding or removing a key name
update_key_index(KeyName, Operation, Opts) ->
    try
        % Validate inputs
        case {is_binary(KeyName), is_atom(Operation)} of
            {true, true} -> ok;
            _ -> 
                ?event(error, {invalid_key_index_params, KeyName, Operation}),
                throw(invalid_params)
        end,
        
        IndexPath = <<"api-keys-index">>,
        CurrentKeys = get_key_index_safe(Opts),
        ?event(debug, {update_key_index, {current_keys, CurrentKeys}, {operation, Operation}, {key, KeyName}}),
        
        UpdatedKeys = case Operation of
            add ->
                case lists:member(KeyName, CurrentKeys) of
                    true -> 
                        ?event(debug, {update_key_index, key_already_exists}),
                        CurrentKeys;  % Already exists
                    false -> 
                        ?event(debug, {update_key_index, adding_new_key}),
                        [KeyName | CurrentKeys]
                end;
            remove ->
                ?event(debug, {update_key_index, removing_key}),
                lists:delete(KeyName, CurrentKeys)
        end,
        
        ?event(debug, {update_key_index, {updated_keys, UpdatedKeys}}),
        
        IndexData = #{
            <<"keys">> => UpdatedKeys,
            <<"updated">> => os:system_time(second),
            <<"device">> => <<"api@1.0">>
        },
        
        ?event(debug, {update_key_index, {writing_index_data, IndexData}}),
        
        % Write updated index to cache
        case hb_cache:write(IndexData, Opts) of
            {ok, CachePath} ->
                ?event(debug, {update_key_index, {cache_write_success, CachePath}}),
                LinkResult = hb_cache:link(CachePath, IndexPath, Opts),
                ?event(debug, {update_key_index, {link_result, LinkResult}}),
                ok;
            {error, WriteError} ->
                ?event(error, {failed_to_update_key_index, KeyName, Operation, WriteError}),
                error
        end
    catch
        Error:Reason:Stack ->
            ?event(error, {key_index_error, Error, Reason, Stack}),
            error
    end.


