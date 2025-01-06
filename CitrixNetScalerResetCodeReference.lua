--------------------------------------------------------------------------------
-- Citrix ADC (NetScaler) Reset Code Post-Dissector
-- Original idea and code by Todd Maxey (github.com/toddmaxey)
-- Updated to incorporate recommended improvements for stable operation
-- References:
--  - https://support.citrix.com/article/CTX200852/citrix-adc-netscaler-reset-codes-reference
--  - Wireshark Lua API documentation
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- 1. Define a new protocol
--------------------------------------------------------------------------------

local citrix_reset_proto = Proto("citrix_reset", "Citrix ADC Reset Codes")

--------------------------------------------------------------------------------
-- 2. Define the fields for this protocol
--------------------------------------------------------------------------------

citrix_reset_proto.fields.reset_window = ProtoField.uint16(
    "citrix_reset.window_size",
    "Citrix Reset Window Size",
    base.DEC
)

--------------------------------------------------------------------------------
-- 3. Define field extractors from the existing TCP dissector
--------------------------------------------------------------------------------

local f_tcp_srcport       = Field.new("tcp.srcport")
local f_tcp_dstport       = Field.new("tcp.dstport")
local f_tcp_window_size   = Field.new("tcp.window_size")       -- or "tcp.window_size_value"
local f_tcp_flags_reset   = Field.new("tcp.flags.reset")

--------------------------------------------------------------------------------
-- 4. Define the lookup table for Citrix ADC reset codes
--------------------------------------------------------------------------------

local window_size_lookup = {
    [8196]  = "SSL bad record.",
    [8201]  = "NSDBG_RST_SSTRAY, 8201 – NSDBG_RST_SSTRAY",
    [8202]  = "NSDBG_RST_CSTRAY: Triggered when the NetScaler receives data on a connection with an expired SYN cookie.",
    [8204]  = "Client retransmitted SYN with the wrong sequence number.",
    [8205]  = "ACK number in the final ACK from peer during connection establishment is wrong.",
    [8206]  = "Received a bad packet in TCPS_SYN_SENT state (non-RST). Possibly reused 4-tuple from old connection.",
    [8207]  = "Received SYN on an established connection within the window. Protects from spoofing attacks.",
    [8208]  = "Reset after receiving more than the configured number of duplicate retransmissions.",
    [8209]  = "Memory allocation failure (system out of memory).",
    [8210]  = "HTTP DoS protection triggered by a bad client request.",
    [8211]  = "Cleanup of idle connections.",
    [8212]  = "Stray SYN packet with no listening service or invalid SYN cookie.",
    [8213]  = "Sure Connect feature, bad client sending post on a closing connection.",
    [8214]  = "MSS in SYN exceeded NIC/VLAN MTU.",
    [9100]  = "NSDBG_RST_ORP: Orphan HTTP connection timed out waiting for completion.",
    [9212]  = "HTTP invalid request.",
    [9214]  = "Cache resource store failed.",
    [9216]  = "Cache async no memory.",
    [9217]  = "HTTP state machine error from receiving content longer than specified Content-Length.",
    [9218]  = "Terminated due to extra orphan data.",
    [9219]  = "NSB allocation failure.",
    [9220]  = "Could not allocate new NSB (various reasons).",
    [9221]  = "vurl includes an invalid domain shard.",
    [9222]  = "Response was RFC-noncompliant (e.g., both Content-Length and Transfer-Encoding invalid).",
    [9300]  = "NSDBG_RST_ZSSSR: Zombie timer/idle timeout or service-down event.",
    [9301]  = "NSDBG_RST_ZSSSR: Zombie timer/idle timeout or service-down event.",
    [9302]  = "NSDBG_RST_ZSSSR: Zombie timer/idle timeout or service-down event.",
    [9303]  = "NSDBG_RST_ZSSSR: Zombie timer/idle timeout or service-down event.",
    [9304]  = "NSDBG_RST_LINK_GIVEUPS: Freed session after zero window probe limit exceeded.",
    [9305]  = "Server ACK to SYN had an invalid ACK number.",
    [9306]  = "TCP buffering undone due to duplicate TCPB enablement.",
    [9307]  = "Small window protection triggered reset.",
    [9308]  = "Small window protection triggered reset.",
    [9309]  = "Small window protection triggered reset.",
    [9310]  = "TCP keepalive probing failed.",
    [9311]  = "DHT retry failed.",
    [9400]  = "Reset server connections in reusepool that are not reusable.",
    [9401]  = "Reset older connections to free capacity for new ones or when removing an entity with active connections.",
    [9450]  = "SQL HS failed.",
    [9451]  = "SQL response failed.",
    [9452]  = "SQL request list failed.",
    [9453]  = "SQL UNK not linked.",
    [9454]  = "SQL NSB hold failed.",
    [9455]  = "SQL Server First Packet.",
    [9456]  = "SQL login response arrived before request.",
    [9457]  = "SQL server login failed.",
    [9458]  = "SQL no memory.",
    [9459]  = "SQL bad server.",
    [9460]  = "SQL link failed.",
    [9600]  = "Reset if # of pkts with Sequence/ACK mismatch > nscfg_max_orphan_pkts.",
    [9601]  = "Reset if # of data pkts with Sequence/ACK mismatch > nscfg_max_orphan_pkts.",
    [9602]  = "SSL VPN CS probe limit exceeded.",
    [9700]  = "NSDBG_RST_PASS: RST forwarded from client or server.",
    [9701]  = "NSDBG_RST_ACK_PASS: RST + ACK forwarded from client or server.",
    [9702]  = "Data received after FIN.",
    [9704]  = "NSB dropped (hold limit or transaction error).",
    [9800]  = "NSDBG_RST_PROBE: Monitoring service reset due to timeout.",
    [9810]  = "Responses match the configured NAI status code.",
    [9811]  = "NSDBG_RST_ERRHANDLER: Used with SSL after sending a Fatal Alert.",
    [9812]  = "Connection flushing: existing IP removed from configuration.",
    [9813]  = "Closing the SSF connection.",
    [9814]  = "NSDBG_RST_PETRIGGER: Reset triggered by policy engine match.",
    [9816]  = "Bad SSL record.",
    [9817]  = "SSL connection changed while updating bound certificate.",
    [9818]  = "Bad SSL header value.",
    [9819]  = "Failed to allocate memory for SPCB.",
    [9820]  = "SSL card operation failed.",
    [9821]  = "SSL feature disabled; resetting the connection.",
    [9822]  = "SSL cipher changed; old-cipher connection flush.",
    [9823]  = "Malformed NSC_AAAC cookie or memory failure in certificate processing.",
    [9824]  = "Reset on AAA orphan connections.",
    [9825]  = "DBG_WRONG_GSLBRECDLEN: MEP error reset code, typically from version mismatch.",
    [9826]  = "Insufficient memory for NET buffers.",
    [9827]  = "Reset on SSL config change.",
    [9829]  = "Reset on GSLB other site down/out of reach.",
    [9830]  = "Reset for sessions matching ACL DENY rule.",
    [9831]  = "Connection had no application data but needed it.",
    [9832]  = "Application error.",
    [9833]  = "Fatal SSL error.",
    [9834]  = "Reset while flushing all SPCB (fips or hsm init).",
    [9835]  = "DTLS record too large.",
    [9836]  = "DTLS record zero length.",
    [9837]  = "SSLv2 record too large.",
    [9838]  = "NSBE_DBG_RST_SSL_BAD_RECORD: SSL record lookup error.",
    [9839]  = "SSL max NSB hold limit reached.",
    [9841]  = "SSL/DTLS split packet failure.",
    [9842]  = "SSL NSB allocation failure.",
    [9843]  = "Monitor wide IP probe.",
    [9844]  = "SSL reneg max NSB limit or allocation failure.",
    [9845]  = "Reset on Appsec policy.",
    [9846]  = "Delta compression aborted or failed.",
    [9847]  = "Delta compression aborted or failed.",
    [9848]  = "Reset on new SSL connection accepted during config change.",
    [9849]  = "GSLB conflict from misconfiguration.",
    [9850]  = "DNS TCP connection untrackable (compact NSB failure, etc.).",
    [9851]  = "DNS TCP failure (invalid payload length, etc.).",
    [9852]  = "RTSP (ALG) session handling error.",
    [9853]  = "MSSQL Auth response error.",
    [9854]  = "Indirect GSLB sites tried to establish connection.",
    [9855]  = "For HTTP/SSL vservers, SO threshold reached.",
    [9856]  = "AppFW ASYNC failure.",
    [9857]  = "Reset while flushing HTTP waiting PCB.",
    [9858]  = "Reset on re-chunk abort.",
    [9859]  = "New client connection deferrable by server on the label.",
    [9860]  = "pcb->link cleaned, connection reset.",
    [9861]  = "Push vserver connection reset if push disabled on client vserver.",
    [9862]  = "Reset to client for duplicate server connection.",
    [9863]  = "Reset old connection if new connection established but old one not freed.",
    [9864]  = "CVPN HINFO restore failed.",
    [9865]  = "CVPN MCMX error.",
    [9866]  = "URL policy transform error.",
    [9868]  = "MSSQL login errors.",
    [9870]  = "SQL login parse error.",
    [9871]  = "MSSQL memory allocation failure.",
    [9872]  = "Websocket upgrade request dropped due to disabled Websocket in HTTP profile.",
    [9873]  = "Agsvc MCMX failure.",
    [9874]  = "NSB hold limit reached.",
    [9875]  = "RADIUS request parse error.",
    [9876]  = "RADIUS response parse error.",
    [9877]  = "RADIUS request dropped.",
    [9878]  = "RADIUS response dropped.",
    [9879]  = "Invalid RADIUS request.",
    [9880]  = "Invalid RADIUS response.",
    [9881]  = "RADIUS no memory.",
    [9882]  = "RADIUS link failed.",
    [9883]  = "RADIUS unlinked.",
    [9884]  = "RADIUS unexpected error.",
    [9885]  = "RADIUS unhandled response.",
    [9886]  = "RADIUS unhandled request.",
    [9887]  = "RADIUS missing UNK.",
    [9888]  = "RADIUS wrong UNK.",
    [9889]  = "RADIUS UNK refcnt.",
    [9890]  = "RADIUS UNK purge.",
    [9891]  = "RADIUS tunnel reject.",
    [9892]  = "RADIUS unknown error.",
    [9893]  = "Monitor probe reset.",
    [9894]  = "Monitor mark down.",
    [9895]  = "Monitor probe flush.",
    [9896]  = "Monitor payload too small.",
    [9897]  = "SNMP wrong packet.",
    [9898]  = "SNMP wrong version.",
    [9899]  = "SNMP wrong community.",
    [9900]  = "SNMP wrong community.",
    [9901]  = "SNMP wrong PDU.",
    [9902]  = "SNMP wrong type.",
    [9903]  = "SNMP wrong request ID.",
    [9904]  = "SNMP wrong error status.",
    [9905]  = "SNMP wrong error index.",
    [9906]  = "SNMP no such object.",
    [9907]  = "SNMP no such instance.",
    [9908]  = "SNMP too big.",
    [9909]  = "SNMP read only.",
    [9910]  = "SNMP gen error.",
    [9911]  = "SNMP wrong encoding.",
    [9912]  = "SNMP wrong length.",
    [9913]  = "SNMP wrong value.",
    [9914]  = "SNMP no memory.",
    [9915]  = "SNMP no response.",
    [9916]  = "SNMP not writable.",
    [9917]  = "SNMP auth error.",
    [9918]  = "SNMP wrong digest.",
    [9919]  = "SNMP bad value.",
    [9920]  = "SNMP not in MIB.",
    [9921]  = "SNMP too many indices.",
    [9922]  = "SNMP not enough indices.",
    [9923]  = "SNMP wrong index type.",
    [9924]  = "SNMP wrong index length.",
    [9925]  = "SNMP wrong index value.",
    [9926]  = "SNMP no such name.",
    [9927]  = "SNMP wrong varbind list.",
    [9928]  = "SNMP end of MIB.",
    [9929]  = "SNMP too big for packet.",
    [9930]  = "SNMP no such view.",
    [9931]  = "SNMP no such context.",
    [9932]  = "SNMP no such user.",
    [9933]  = "SNMP not in view.",
    [9934]  = "SNMP unsupported security level.",
    [9935]  = "SNMP unsupported auth protocol.",
    [9936]  = "SNMP unsupported priv protocol.",
    [9937]  = "SNMP unknown user name.",
    [9938]  = "SNMP unknown engine ID.",
    [9939]  = "SNMP wrong security model.",
    [9940]  = "SNMP bad security level.",
    [9941]  = "SNMP bad engine ID.",
    [9942]  = "SNMP bad user name.",
    [9943]  = "SNMP bad auth protocol.",
    [9944]  = "SNMP bad priv protocol.",
    [9945]  = "SNMP bad security name.",
    [9946]  = "SNMP bad security model.",
    [9947]  = "SNMP bad message.",
    [9948]  = "SNMP bad PDU.",
    [9949]  = "SNMP bad SPI.",
    [9950]  = "SNMP bad context.",
    [9951]  = "SNMP bad security state ref.",
    [9952]  = "SNMP bad security name.",
    [9953]  = "SNMP bad community.",
    [9954]  = "SNMP bad community uses.",
    [9955]  = "SNMP bad community name.",
    [9956]  = "SNMP bad community indexing.",
    [9957]  = "SNMP bad party.",
    [9958]  = "SNMP bad party uses.",
    [9959]  = "SNMP bad party name.",
    [9960]  = "SNMP bad party indexing.",
    [9961]  = "SNMP bad party TDomain.",
    [9962]  = "SNMP bad party TAddress.",
    [9963]  = "SNMP bad party identity.",
    [9964]  = "SNMP bad party TTimeout.",
    [9965]  = "SNMP bad party TMaxMessageSize.",
    [9966]  = "SNMP bad party priv proto.",
    [9967]  = "SNMP bad party auth clock.",
    [9968]  = "SNMP bad party auth lifetime.",
    [9969]  = "SNMP bad party auth private.",
    [9970]  = "SNMP bad party auth public.",
    [9971]  = "SNMP bad party auth clock skew.",
    [9972]  = "SNMP bad party auth truncated.",
    [9973]  = "SNMP bad party auth wrong digest.",
    [9974]  = "SNMP bad party auth wrong.",
    [9975]  = "SNMP bad context.",
    [9976]  = "SNMP bad context uses.",
    [9977]  = "SNMP bad context name.",
    [9978]  = "SNMP bad context indexing.",
    [9979]  = "SNMP bad ACL.",
    [9980]  = "SNMP bad ACL uses.",
    [9981]  = "SNMP bad ACL name.",
    [9982]  = "SNMP bad ACL indexing.",
    [9983]  = "SNMP bad ACL party.",
    [9984]  = "SNMP bad ACL context.",
    [9985]  = "SNMP bad ACL privs.",
    [9986]  = "SNMP bad view.",
    [9987]  = "SNMP bad view uses.",
    [9988]  = "SNMP bad view name.",
    [9989]  = "SNMP bad view indexing.",
    [9990]  = "SNMP bad view subtree.",
    [9991]  = "SNMP bad view mask.",
    [9992]  = "SNMP bad view type.",
    [9993]  = "SNMP bad view storage.",
    [9994]  = "SNMP bad view status.",
    [9995]  = "SNMP bad MIB.",
    [9996]  = "SNMP bad MIB name.",
    [9997]  = "SNMP bad MIB syntax.",
    [9998]  = "SNMP bad MIB write syntax.",
    [9999]  = "SNMP bad MIB access.",
    [10000] = "SNMP bad MIB status.",
    [10001] = "SNMP bad MIB indexes.",
    [10002] = "SNMP bad MIB deps.",
    [10003] = "SNMP bad MIB inits."
}

--------------------------------------------------------------------------------
-- 5. Dissection function
--------------------------------------------------------------------------------

function citrix_reset_proto.dissector(buffer, pinfo, tree)
    -- Fetch extracted fields
    local tcp_srcport = f_tcp_srcport()
    local tcp_dstport = f_tcp_dstport()
    local tcp_rstflag = f_tcp_flags_reset()
    local tcp_win     = f_tcp_window_size()

    -- If any required fields are nil, no further processing
    if not (tcp_srcport and tcp_dstport and tcp_rstflag and tcp_win) then
        return
    end

    -- Convert to numeric
    local rst_val = tonumber(tostring(tcp_rstflag))
    local win_val = tonumber(tostring(tcp_win))

    -- Check if the RST flag is set
    if rst_val == 1 and win_val then
        local description = window_size_lookup[win_val]
        if description then
            -- Create a subtree for Citrix ADC info
            local subtree = tree:add(
                citrix_reset_proto,
                buffer(),
                "Citrix ADC Reset Info"
            )
            -- Add window size field
            local item = subtree:add(
                citrix_reset_proto.fields.reset_window,
                buffer(),
                win_val
            )
            -- Append textual description
            item:append_text(" (" .. description .. ")")
        end
    end
end

--------------------------------------------------------------------------------
-- 6. Register the post-dissector
--------------------------------------------------------------------------------

register_postdissector(citrix_reset_proto)
