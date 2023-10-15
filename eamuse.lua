
-- Wireshark addon to easily read data from Eamusement packets 
-- Postdissecotr

local eamusement_info =
{
    version = "1.0.0",
    author = "Kuro",
    description = "Partialy decodes Eamusement packets",
    repository = "https://github.com/pogof/Bemani-Shark"
}
set_plugin_info(eamusement_info)


-- Define new protocol
local eamu_p = Proto.new("EAMUSEMENT","Eamusement gameserver communication")


-- Define new fields
local pf = {
    eapacket = ProtoField.string("eamu.packet", "Eamu raw data"), -- Raw data once again
    epacket_ready = ProtoField.string("eamu.packet_ready", "Data Ready to copy"), -- Data that can be used elsewhere, still encrypted and compressed 
    eacomp = ProtoField.string("eamu.comp", "X-Compress"), -- Information about compression
    eahost = ProtoField.string("eamu.host", "Host"), -- Information about server host
    eauseragent = ProtoField.string("eamu.user_agent", "User-Agent"), -- Not really needed for anything
    eaconlen = ProtoField.string("eamu.content_length", "Content-Length"), -- Length of data in packet
    eaencr = ProtoField.string("eamu.encryption", "X-Eamuse-Info") -- X-Eamuse-Info
    --eadate = ProtoField.string("eamu.date", "Date") -- Date sent to game from server | Disabled because it is not important for my work
}
eamu_p.fields = pf


-- Load apropriate information from packet



eamu_is = Field.new("http.user_agent") -- Is the packet Eamu?
eamu_header = Field.new("http.request.line") -- Info about compression and encryption received
eamu_header_sent = Field.new("http.response.line") -- Info about compression and encryption sent
eamu_data = Field.new("data.data") -- Raw data

-- Main postdissector function that will run on each frame/packet
function eamu_p.dissector(tvb,pinfo,tree)

    -- Copy existing field(s) into table for processing
    eamu_is_table = {eamu_is()}
    eamu_header_table = {eamu_header()}
    eamu_header_table_sent = {eamu_header_sent()}
    eamu_data_table = {eamu_data()}

    -- Create new tree
    local subtree = nil
    subtree = tree:add(eamu_p)

    -- Find, clean and display all info from header - FOR RECEIVED
    for i, header_info in ipairs(eamu_header_table) do
        if(string.find(tostring(header_info.value), "Host")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("Host: ", "")
            subtree:add(pf.eahost, str)

        elseif(string.find(tostring(header_info.value), "User")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("User[-]Agent: ", "")
            subtree:add(pf.eauseragent, str)

        elseif(string.find(tostring(header_info.value), "Content")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("Content[-]Length: ", "")
            subtree:add(pf.eaconlen, str)

        elseif(string.find(tostring(header_info.value), "X-Eamuse")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("X[-]Eamuse[-]Info: ", "")
            subtree:add(pf.eaencr, str)

        elseif(string.find(tostring(header_info.value), "X-Compress")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("X[-]Compress: ", "")
            subtree:add(pf.eacomp, str)
        end
    end

    -- Find, clean and display all info from header - FOR SENT
    for i, header_info in ipairs(eamu_header_table_sent) do
        if(string.find(tostring(header_info.value), "user")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("user[-]agent: ", "")
            subtree:add(pf.eauseragent, str)

        elseif(string.find(tostring(header_info.value), "content")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("content[-]cength: ", "")
            subtree:add(pf.eaconlen, str)

        elseif(string.find(tostring(header_info.value), "x-eamuse")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("x[-]eamuse[-]info: ", "")
            subtree:add(pf.eaencr, str)

        elseif(string.find(tostring(header_info.value), "x-compress")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")
            str = str:gsub("x[-]compress: ", "")
            subtree:add(pf.eacomp, str)
--[[         elseif(string.find(tostring(header_info.value), "date")) then
            str = tostring(header_info.value)
            str = str:gsub("\r\n", "")           -- Date | Disabled because it is not important for my work
            str = str:gsub("date: ", "")
            subtree:add(pf.eadate, str) ]]
        end
    end


    for k, v in ipairs(eamu_data_table) do
        -- process data and add results to the tree
        str = tostring(v.value)
        str = string.lower(str)
        subtree:add(pf.eapacket, str)

        local longdata = "b'"
        for i = 1, string.len(str), 2 do
            hexstr = string.sub(str, i, i + 1)
            hexval = tonumber(hexstr, 16)

            if(0x20 < hexval and hexval < 0x7f) then
                if(hexval == 0x27) then
                    longdata = longdata .. "\\'"
                    -- Replace start and end '' with "" ???? sometimes?
                elseif(hexval == 0x5c) then
                    longdata = longdata .. "\\\\"
                else
                    longdata = longdata .. string.char(hexval)
                end
            elseif(hexval == 0x0a) then
                longdata = longdata .. "\\n"
            elseif(hexval == 0x0d) then
                longdata = longdata .. "\\r"
            elseif(hexval == 0x20) then
                longdata = longdata .. " "
            elseif(hexval == 0x09) then
                longdata = longdata .. "\\t"
            else
                longdata = longdata .. "\\x"
                longdata = longdata .. hexstr
                
            end
        end
        longdata = longdata .. "'"
        subtree:add(pf.epacket_ready, longdata)

    end

end
register_postdissector(eamu_p) -- Register the new protocol as a postdissector
