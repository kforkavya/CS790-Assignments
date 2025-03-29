-- Proto(): Make a new protocol object
-- first arg -> name
-- secong arg -> description
local tor_proto = Proto("TorTLS", "Tor Traffic Detector (TLS)")

-- ProtoField.string(): Make a new field of string type
-- first arg -> abbreviation to be used in filter of Wireshark
-- second arg -> name to be used in subtree display
local tor_field = ProtoField.string("tor", "Is Tor?")
tor_proto.fields = { tor_field }

-- Field.new(<field name>): Fetches an object containing the field value
-- Existence of a field can be verified by looking it up in Wireshark filter.
local tls_handshake_type = Field.new("tls.handshake.type")
local tls_cipher_suites_field = Field.new("tls.handshake.ciphersuites")
local ip_src_field = Field.new("ip.src")
local ip_dst_field = Field.new("ip.dst")

-- 18 Cipher Suites (Common in ClientHello of TLS)
local tor_cipher_suites = {
    0x1301, 0x1302, 0x1303, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0x00ff, 0xcca9, 
    0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035
}

local tor_IPs_found = {}

local function lookup(to_find, arr)
    for _, val in ipairs(arr) do
        if val == to_find then
            return true
        end
    end
    return false
end

local function insert_if_not_exists(to_insert, arr)
    if not lookup(to_insert, arr) then
        table.insert(arr, to_insert)
    end
end

local function is_TOR_ip(ip)
    return lookup(ip, tor_IPs_found)
end

local function are_lists_equivalent(list1, list2)
    if #list1 ~= #list2 then
        return false
    end

    for _, val in ipairs(list1) do
        if not lookup(val, list2) then
            return false
        end
    end

    for _, val in ipairs(list2) do
        if not lookup(val, list1) then
            return false
        end
    end

    return true
end

-- Get the original TCP dissector
local tcp_dissector = Dissector.get("tcp")

function tor_proto.dissector(buffer, pinfo, tree)
    -- Call the original TCP dissector first
    tcp_dissector:call(buffer, pinfo, tree)

    local handshake_type_fi = tls_handshake_type()
    local cipher_suites_fi = tls_cipher_suites_field()
    local ip_src_fi = ip_src_field()
    local ip_dst_fi = ip_dst_field()

    -- Ensure it's a TLS ClientHello packet
    if handshake_type_fi and handshake_type_fi.value == 1 and cipher_suites_fi then
        -- .range converts it to a TvbRange and bytes() turns it to a ByteArray
        local cipher_suites_bytes = cipher_suites_fi.range:bytes()
        local cipher_suits = {}

        for i = 0, cipher_suites_bytes:len() - 2, 2 do
            local cipher_id = cipher_suites_bytes(i, 2):uint()
            table.insert(cipher_suits, cipher_id)
        end

        -- If all the cipher suites are found, add the IP to the list
        if are_lists_equivalent(cipher_suits, tor_cipher_suites) then
            insert_if_not_exists(ip_dst_fi.value, tor_IPs_found)
        end
    end

    if ip_src_fi and ip_dst_fi then
        if is_TOR_ip(ip_src_fi.value) or is_TOR_ip(ip_dst_fi.value) then
            -- Modify Protocol column
            pinfo.cols.protocol:append(" (Tor!)")

            -- Add a subtree to the existing TLS tree
            local tls_tree = tree:add(tor_proto, buffer(), "Tor Traffic Detection")
            tls_tree:add(tor_field, "Tor!")
        end
    end
end

DissectorTable.get("ip.proto"):add(6, tor_proto)