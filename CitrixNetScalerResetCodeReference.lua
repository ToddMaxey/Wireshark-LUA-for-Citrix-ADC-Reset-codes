-- Idea and code by Todd Maxey
-- github.com/toddmaxey
-- WireShark LUA script for decoding Citrix ADC (NetScaler) Reset Codes
-- Based on https://support.citrix.com/article/CTX200852/citrix-adc-netscaler-reset-codes-reference

-- Reset code to description table
-- Define a new protocol
local tcp_windows_proto = Proto("tcp_windows", "TCP Windows Error Code")

-- Define the fields
tcp_windows_proto.fields.window = ProtoField.uint16("tcp_windows.window", "Window Size", base.DEC)

-- Define field extractors
local f_tcp_srcport = Field.new("tcp.srcport")
local f_tcp_dstport = Field.new("tcp.dstport")
local f_tcp_window_size = Field.new("tcp.window_size")
local f_tcp_flags_reset = Field.new("tcp.flags.reset")

-- Define the lookup table
local window_size_lookup = {
    [8196] = "SSL bad record.",
    [8201] = "NSDBG_RST_SSTRAY, 8201 – NSDBG_RST_SSTRAY",
    [8202] = "NSDBG_RST_CSTRAY: This code is triggered when the NetScaler appliance receives data through a connection, which does not have a PCB, and its SYN cookie has expired.",
    [8204] = "Client retransmitted SYN with the wrong sequence number.",
    [8205] = "ACK number in the final ACK from peer during connection establishment is wrong.",
    [8206] = "Received a bad packet in TCPS_SYN_SENT state (non RST packet). Usually happens if the 4 tuples are reused and you receive packet from the old connection.",
    [8207] = "Received SYN on established connection which is within the window. Protects from spoofing attacks.",
    [8208] = "Resets the connection when you receive more than the configured value of duplicate retransmissions.",
    [8209] = "Could not allocate memory for the packet, system out of memory.",
    [8210] = "HTTP DoS protection feature error, bad client request.",
    [8211] = "Cleanup of idle connections.",
    [8212] = "Stray packet (no listening service or listening service is present but SYN cookie does not match or there is no corresponding connection information). 8212 is specifically for SYN stray packets.",
    [8213] = "Sure Connect feature, bad client sending post on connection which is closing.",
    [8214] = "MSS sent in SYN exceeded the MSS corresponding to NIC MTU and/or VLAN MTU.",
    [9100] = "NSDBG_RST_ORP: This code refers to an orphan HTTP connection. Probably, a connection where data is initially seen either from the server or client, but stopped because of some reason, without closing the TCP session. It indicates that the client request was not properly terminated. Therefore, the NetScaler appliance waits for the request to be completed. After a timeout, the NetScaler appliance resets the connection with the code 9100.",
    [9212] = "HTTP Invalid request.",
    [9214] = "Cache res store failed.",
    [9216] = "Cache async no memory.",
    [9217] = "HTTP state machine error because of more than content length body.",
    [9218] = "Terminated due to extra orphan data.",
    [9219] = "NSB allocation failure.",
    [9220] = "Cannot allocate new NSB and so many other reasons.",
    [9221] = "vurl comes with a domain shard that’s no longer valid.",
    [9222] = "This is sent when the response is RFC non-compliant. The issue is caused by both Content-Length and Transfer-Encoding in response being invalid, which may lead to a variety of attacks and leads to the reset.",
    [9300] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9301] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9302] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9303] = "NSDBG_RST_ZSSSR: This code refers to an idle timeout or a zombie timeout. This code is set by the zombie connection cleanup routine, a connection has timed out. When the status of a service is down, existing TCP connections to that service are reset with this code (TCP window size 9300/9301, zombie timer). If the NetScaler appliance receives a segment from one of these connections, which is already reset, send another reset (TCP window size 8201, stray packet).",
    [9304] = "NSDBG_RST_LINK_GIVEUPS: This reset code might be part of a backend-persistence mechanism, which is used to free resources on the NetScaler. By default, the NetScaler uses a zero window probe 7 times before giving up and resetting the connection. By disabling this mechanism, the appliance holds the sessions without this limit. The following is the command to disable the persistence probe limit: root@ns# nsapimgr -ys limited_persistprobe=0 The default value is 1, which limits to 7 probes, which is around 2 minutes. Setting the value to zero disables it and keeps the session open as long as the server sends an ACK signal in response to the probes.",
    [9305] = "Server sent back ACK to our SYN (ACK number did not match).",
    [9306] = "TCP buffering is undone due to duplicate TCPB enablement.",
    [9307] = "Small window protection feature resetting the connection.",
    [9308] = "Small window protection feature resetting the connection.",
    [9309] = "Small window protection feature resetting the connection.",
    [9310] = "TCP KA probing failed.",
    [9311] = "DHT retry failed.",
    [9400] = "Reset server connection which are in reusepool and are not reusable because of TCP or Session level properties. Usually this is done when we need to open new connections but there is limit on connection we can open to the server and there are some already built up connections which are not reusable.",
    [9401] = "When you reach maximum system capacity flushing existing connections based time order to accommodate new connections. Or when we remove an configured entity which as associated connections those connection will be reset.",
    [9450] = "SQL HS failed.",
    [9451] = "SQL response failed.",
    [9452] = "SQL request list failed.",
    [9453] = "SQL UNK not linked.",
    [9454] = "SQL NSB hold failed",
    [9455] = "SQL Server First Packet",
    [9456] = "SQL Login response before request",
    [9457] = "SQL server login failed",
    [9458] = "SQL no memory",
    [9459] = "SQL bad server",
    [9460] = "SQL link failed",
    [9600] = "Reset when Number of packets with Sequence ACK mismatch > nscfg_max_orphan_pkts",
    [9601] = "Reset when Number of data packets with Sequence ACK mismatch > nscfg_max_orphan_pkts",
    [9602] = "When SSL VPN CS probe limit exceeded",
    [9700] = "NSDBG_RST_PASS: This code indicates that the NetScaler appliance receives a TCP RST code from either the client or the server, and is transferring it. For example, the back end server sends a RST code, and the NetScaler appliance forwards it to the client with this code.",
    [9701] = "NSDBG_RST_NEST / NSDBG_RST_ACK_PASS: The NetScaler software release 9.1 and the later versions, this code indicates #define NSBE_DBG_RST_ACK_PASS. It indicates that a RST code was forwarded as in the preceding RST code 9700, and the ACK flag was also set.",
    [9702] = "The data received after FIN is received.",
    [9704] = "Reset when NSB dropped due to hold limit or error in transaction etc.",
    [9800] = "NSDBG_RST_PROBE: This connections used for monitoring the service are reset due to timeout.",
    [9810] = "When responses match the configured NAI status code.",
    [9811] = "NSDBG_RST_ERRHANDLER: This reset code is used with SSL. After sending a Fatal Alert, the NetScaler sends a RST packet with this error code. If the client does not display any supported ciphers to the NetScaler appliance, the appliance sends a Fatal Alert and then this RST packet.",
    [9812] = "Connection flushing because existing IP address is removed from the configuration.",
    [9813] = "Closing the SSF connection.",
    [9814] = "NSDBG_RST_PETRIGGER: This reset code is used when a request or response matches a Policy Engine policy, whose action is RESET.",
    [9816] = "Bad SSL record.",
    [9817] = "SSL connection received at the time of bound certificate changing (configuration change).",
    [9818] = "Bad SSL header value.",
    [9819] = "Reset on failing to allocate memory for SPCB.",
    [9820] = "SSL card operation failed.",
    [9821] = "SSL feature disabled, reset the connection.",
    [9822] = "SSL cipher changed, flush the connection created for old cipher.",
    [9823] = "Reset when the NSC_AAAC cookie is malformed in a request or /vpn/apilogin.html request does not have a query part, memory allocation failures in certificate processing.",
    [9824] = "Reset on AAA orphan connections.",
    [9825] = "DBG_WRONG_GSLBRECDLEN: This code is an MEP error reset code, typically between mixed versions.",
    [9826] = "Not enough memory for NET buffers",
    [9827] = "Reset on SSL config change",
    [9829] = "Reset on GSLB other site down or out of reach",
    [9830] = "Reset on sessions matching ACL DENY rule",
    [9831] = "Use it if no application data exist, but required",
    [9832] = "Application error",
    [9833] = "Fatal SSL error",
    [9834] = "Reset while flushing all SPCB, during fips or hsm init",
    [9835] = "DTLS record too large",
    [9836] = "DTLS record zero length",
    [9837] = "SSLV2 record too large",
    [9838] = "NSBE_DBG_RST_SSL_BAD_RECORD: This code refers to error looking up SSL record when handling a request or a response.",
    [9839] = "SSL MAX NSB hold limit reached",
    [9841] = "SSL/DTLS split packet failure",
    [9842] = "SSL NSB allocation failure",
    [9843] = "Monitor wide IP probe",
    [9844] = "SSL reneg max NSB limit reached or alloc failure",
    [9845] = "Reset on Appsec policy",
    [9846] = "Delta compression aborted or failed",
    [9847] = "Delta compression aborted or failed",
    [9848] = "Reset on connection accepted during configuration change(SSL)",
    [9849] = "Reset on GSLB conflict due to mis configuration",
    [9850] = "DNS TCP connection untrackable due to failure of compact NSB etc",
    [9851] = "DNS TCP failure ( invalid payload len etc)",
    [9852] = "RTSP (ALG) session handling error",
    [9853] = "MSSQL Auth response error",
    [9854] = "Indirect GSLB sites tried to establish connection",
    [9855] = "For HTTP/SSL vservers, SO threshold has reached",
    [9856] = "Reset on Appfw ASYNC failure",
    [9857] = "Reset on Flushing HTTP waiting PCB",
    [9858] = "Reset on Rechunk abort",
    [9859] = "A new client connection request was made deferrable by server on the label",
    [9860] = "The pcb->link of this connection was cleaned for some reason, so resetting this pcb",
    [9861] = "Connection on a push vserver, when push disabled on client vserver",
    [9862] = "Reset to Client as it resulted in duplicate server connection",
    [9863] = "Reset to old connection when new connection is established and old one is still not freed",
    [9864] = "CVPN HINFO restore failed",
    [9865] = "CVPN MCMX error",
    [9866] = "URL policy transform error",
    [9868] = "MSSQL login errors",
    [9870] = "SQL login parse error",
    [9871] = "MSSQL memory allocation failure",
    [9872] = "Websocket upgrade request dropped due to websocket disabled in http profile",
    [9873] = "Agsvc MCMX failure",
    [9874] = "NSB hold limit reached",
    [9875] = "RADIUS request parse error",
    [9876] = "RADIUS response parse error",
    [9877] = "RADIUS request drop",
    [9878] = "RADIUS response drop",
    [9879] = "Invalid RADIUS request",
    [9880] = "Invalid RADIUS response",
    [9881] = "RADIUS no memory",
    [9882] = "RADIUS link failed",
    [9883] = "RADIUS unlinked",
    [9884] = "RADIUS unexpected error",
    [9885] = "RADIUS unhandled response",
    [9886] = "RADIUS unhandled request",
    [9887] = "RADIUS missing UNK",
    [9888] = "RADIUS wrong UNK",
    [9889] = "RADIUS UNK refcnt",
    [9890] = "RADIUS UNK purge",
    [9891] = "RADIUS tunnel reject",
    [9892] = "RADIUS unknown error",
    [9893] = "Monitor probe reset",
    [9894] = "Monitor mark down",
    [9895] = "Monitor probe flush",
    [9896] = "Monitor payload too small",
    [9897] = "SNMP wrong packet",
    [9898] = "SNMP wrong version",
    [9899] = "SNMP wrong community",
    [9900] = "SNMP wrong community",
    [9901] = "SNMP wrong PDU",
    [9902] = "SNMP wrong type",
    [9903] = "SNMP wrong request id",
    [9904] = "SNMP wrong error status",
    [9905] = "SNMP wrong error index",
    [9906] = "SNMP no such object",
    [9907] = "SNMP no such instance",
    [9908] = "SNMP too big",
    [9909] = "SNMP read only",
    [9910] = "SNMP gen error",
    [9911] = "SNMP wrong encoding",
    [9912] = "SNMP wrong length",
    [9913] = "SNMP wrong value",
    [9914] = "SNMP no memory",
    [9915] = "SNMP no response",
    [9916] = "SNMP not writable",
    [9917] = "SNMP auth error",
    [9918] = "SNMP wrong digest",
    [9919] = "SNMP bad value",
    [9920] = "SNMP not in mib",
    [9921] = "SNMP too many indices",
    [9922] = "SNMP not enough indices",
    [9923] = "SNMP wrong index type",
    [9924] = "SNMP wrong index length",
    [9925] = "SNMP wrong index value",
    [9926] = "SNMP no such name",
    [9927] = "SNMP wrong varbind list",
    [9928] = "SNMP end of mib",
    [9929] = "SNMP too big for packet",
    [9930] = "SNMP no such view",
    [9931] = "SNMP no such context",
    [9932] = "SNMP no such user",
    [9933] = "SNMP not in view",
    [9934] = "SNMP unsupported security level",
    [9935] = "SNMP unsupported auth protocol",
    [9936] = "SNMP unsupported priv protocol",
    [9937] = "SNMP unknown user name",
    [9938] = "SNMP unknown engine ID",
    [9939] = "SNMP wrong security model",
    [9940] = "SNMP bad security level",
    [9941] = "SNMP bad engine ID",
    [9942] = "SNMP bad user name",
    [9943] = "SNMP bad auth protocol",
    [9944] = "SNMP bad priv protocol",
    [9945] = "SNMP bad security name",
    [9946] = "SNMP bad security model",
    [9947] = "SNMP bad message",
    [9948] = "SNMP bad PDU",
    [9949] = "SNMP bad SPI",
    [9950] = "SNMP bad context",
    [9951] = "SNMP bad security state ref",
    [9952] = "SNMP bad security name",
    [9953] = "SNMP bad community",
    [9954] = "SNMP bad community uses",
    [9955] = "SNMP bad community name",
    [9956] = "SNMP bad community indexing",
    [9957] = "SNMP bad party",
    [9958] = "SNMP bad party uses",
    [9959] = "SNMP bad party name",
    [9960] = "SNMP bad party indexing",
    [9961] = "SNMP bad party TDomain",
    [9962] = "SNMP bad party TAddress",
    [9963] = "SNMP bad party identity",
    [9964] = "SNMP bad party TTimeout",
    [9965] = "SNMP bad party TMaxMessageSize",
    [9966] = "SNMP bad party priv proto",
    [9967] = "SNMP bad party auth clock",
    [9968] = "SNMP bad party auth lifetime",
    [9969] = "SNMP bad party auth private",
    [9970] = "SNMP bad party auth public",
    [9971] = "SNMP bad party auth clock skew",
    [9972] = "SNMP bad party auth truncated",
    [9973] = "SNMP bad party auth wrong digest",
    [9974] = "SNMP bad party auth wrong",
    [9975] = "SNMP bad context",
    [9976] = "SNMP bad context uses",
    [9977] = "SNMP bad context name",
    [9978] = "SNMP bad context indexing",
    [9979] = "SNMP bad acl",
    [9980] = "SNMP bad acl uses",
    [9981] = "SNMP bad acl name",
    [9982] = "SNMP bad acl indexing",
    [9983] = "SNMP bad acl party",
    [9984] = "SNMP bad acl context",
    [9985] = "SNMP bad acl privs",
    [9986] = "SNMP bad view",
    [9987] = "SNMP bad view uses",
    [9988] = "SNMP bad view name",
    [9989] = "SNMP bad view indexing",
    [9990] = "SNMP bad view subtree",
    [9991] = "SNMP bad view mask",
    [9992] = "SNMP bad view type",
    [9993] = "SNMP bad view storage",
    [9994] = "SNMP bad view status",
    [9995] = "SNMP bad mib",
    [9996] = "SNMP bad mib name",
    [9997] = "SNMP bad mib syntax",
    [9998] = "SNMP bad mib write syntax",
    [9999] = "SNMP bad mib access",
    [10000] = "SNMP bad mib status",
    [10001] = "SNMP bad mib indexes",
    [10002] = "SNMP bad mib deps",
    [10003] = "SNMP bad mib inits"
    -- ... add more mappings as needed
}

-- Dissection function
function tcp_windows_proto.dissector(buffer, pinfo, tree)
    -- Ensure the packet is TCP
    local tcp_srcport = tonumber(tostring(f_tcp_srcport()))
    local tcp_dstport = tonumber(tostring(f_tcp_dstport()))
    
    if tcp_srcport == nil or tcp_dstport == nil then return end
    
    -- Check if the TCP reset flag is set
    local tcp_reset_flag = tonumber(tostring(f_tcp_flags_reset()))
    
    if tcp_reset_flag == 1 then  -- 1 indicates the reset flag is set
        -- Extract TCP Window Size
        local window_size = tonumber(tostring(f_tcp_window_size()))
        
        -- Look up the description based on window size
        local window_description = window_size_lookup[window_size]
        
        -- Only add the subtree if a description was found
        if window_description then
            local subtree = tree:add(tcp_windows_proto, buffer(), "TCP Windows Error Code")
            subtree:add(tcp_windows_proto.fields.window, window_size):append_text(window_description)
        end
    end
end

-- Register the post-dissector
register_postdissector(tcp_windows_proto)
