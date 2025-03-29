Steps for installation:
- Lua is already available on MacOS/Windows so no need for installation there.
- For Linux, see the official website (https://www.lua.org/download.html) for the steps.

Steps for usage:
- Go to 'About Wireshark' in your Wireshark application.
- Go to its 'Plugins' tab. You'll see paths of many plugins there.
- Most of them will have .../wireshark/4-4/...' in it. Go to this '.../wireshark/4-4/' folder.
- Make a new folder named 'lua' there and inside it paste the lua script.
- We're done then.

Note:
- My wireshark was of version 4.4.5, hence the folder was named '4-4'. It may vary depending on your version.
- I was working on MacOS, hence no sudo privileges were needed for editing the '.../wireshark/4-4/' folder.
  As a Linux, you may have to do those stuff using 'sudo'.