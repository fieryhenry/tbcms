# TBCMailServer

## BETTER METHOD (No server required): <https://github.com/fieryhenry/mailboxhack>

If you want to use the old method, you can still use this tool.

A private server for the mailbox in The Battle Cats.

It allows you to get any cat, talent orb, or item amount you want without
the ban risk of other methods.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/fieryhenry)

## Credits

- [jamesiotio's CITM](https://github.com/jamestiotio/CITM) for the original
    hacking method and the format of the presents. It no longer works due to
    PONOS adding a signature to the server responses as well as other changes.

## Setup

### Manual Setup

I won't go into detail on how to do all of the individual steps such as how to
extract the apk, sign it and setup Frida. You can find tutorials on how to do
all of that online.

1. You will need to modify the game to always verify the
    nyanko-signature of the server responses as we don't know PONOS's private
    key. This can be done using [Frida](https://frida.re/) and this script:

    ```js
    let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhmS2_m" // 64 bit
    // or
    let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhjS2_j" // 32 bit

    // Botan::PK_Verifier::verify_message(...)
    Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
        onLeave: function (retval) {
            retval.replace(0x1)
        }
    })
    ```

    You should only use the function for the correct architecture of your
    device.

    Alternativly you can patch the libnative-lib.so file using a hex editor to
    make the function always return 1.

1. You also need to replace the `https://nyanko-items.ponosgames.com` URL in
    the libnative-lib.so files with your own server URL. This can be done by
    extracting the APK using something like
    [apktool](https://ibotpeaches.github.io/Apktool/) or
    [APKToolGui](https://github.com/AndnixSH/APKToolGUI)
1. Then you can modify the `libnative-lib.so` files in the `lib` folder using a
   hex editor (or notepad maybe).
1. Then you can repack the APK using apktool and sign it using
    [apksigner](https://developer.android.com/studio/command-line/apksigner) or
    [APKToolGui](https://github.com/AndnixSH/APKToolGUI).
1. The URL needs to be the same length as the original URL and it needs to have
    /items/ at the end with underscores padding the rest of the URL.

    The underscores are used to make the URL the same length as the original URL.
    The URL also needs to start with https and so you can use a service like
    [Serveo](https://serveo.net/) to do the https part for you. Just follow the
    instructions on the website. I recommend you to get a custom subdomain so it
    doesn't change (you can use any subdomain as long as the total url length is
    shorter than the original URL).

    Example:

    You can run a command like: `ssh -R myserver:80:localhost:5000 serveo.net`
    You can change the port 5000 to whatever port you want.
    You may need to setup ssh keys for the above to work (follow the given
    instructions) This makes your url: `https://myserver.serveo.net` and then you
    would replace the ponos url with `https://myserver.serveo.net/items/_`.

### Setup Using TBCML

[TBCML](https://github.com/fieryhenry/tbcml) is a library I've made and
recently released to make modding the game easier and more automated. It has a
few features that we can use to setup the apk for the private server. We don't
need to setup Frida as TBCML injects [Frida
Gadget](https://frida.re/docs/gadget/) into the libnative file.

Read the TBCML GitHub page so you can get the library installed. However at the
moment it doesn't work for new apks (I think 12.6.0 and up) due to an issue with
apktool. Also some people have found that tbcml doesn't install for them, so you
might need to do the manual setup for the mail server.

The following script should do what we need and you can modify it for the
version you want and the subdomain you want (see the manual setup section on how
to use
serveo to get a URL):

```python
# see https://github.com/fieryhenry/tbcml
from tbcml import (
    Mod,
    LibPatch,
    StringReplacePatch,
    FridaScript,
    ModLoader,
)

loader = ModLoader("en", "13.1.1")
loader.initialize()

mod = Mod(
    name="Private Server Setup",
    authors="fieryhenry",
    description="A mod that disables signature verification and replaces the nyanko-items url with a custom one",
)

script_64 = """
let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhmS2_m" // 64 bit

// Botan::PK_Verifier::verify_message(...)
Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
    onLeave: function (retval) {
        retval.replace(0x1)
    }
})
"""

script_32 = """
let func_name = "_ZN5Botan11PK_Verifier14verify_messageEPKhjS2_j" // 32 bit

// Botan::PK_Verifier::verify_message(...)
Interceptor.attach(Module.findExportByName("libnative-lib.so", func_name), {
    onLeave: function (retval) {
        retval.replace(0x1)
    }
})
"""

script_32 = FridaScript(
    name="Force Verify Nyanko Signature 32bit",
    content=script_32,
    architectures="32",
    description="Overwrites a botan cryptography function to always return 1",
)
script_64 = FridaScript(
    name="Force Verify Nyanko Signature 64bit",
    content=script_64,
    architectures="64",
    description="Overwrites a botan cryptography function to always return 1",
)

mod.add_script(script_32)
mod.add_script(script_64)

string_patch = StringReplacePatch(
    "https://nyanko-items.ponosgames.com",
    "https://bc.serveo.net/items/",  # replace bc with whatever sub-domain you are using
    "_",
)

patch = LibPatch(
    name="Replace Nyanko Items URL",
    architectures="all",
    patches=string_patch,
)
mod.patches.add_patch(patch)

apk = loader.get_apk()

apk.set_app_name("Battle Cats Private Server")
apk.set_package_name("jp.co.ponos.battlecatsps")

loader.apply(mod)

# loader.initialize_adb()
# loader.install_adb(run_game=True)

print(apk.final_apk_path)

```

You may get `Relocation R32 not supported!` when running the script. This is
normal and you can ignore it.

Instead of using a private server, you might be able to use something like
[mitmproxy](https://mitmproxy.org/) or [Fiddler](https://www.telerik.com/fiddler)
to modify the server responses. This did not work for me as the game always
crashed (works for other requests though) but it might work for you.

## Installation

1. Install [Python](https://www.python.org/downloads/) >= 3.9

1. Run `pip install -U tbcms`

### From Source

1. Install [Git](https://git-scm.com/downloads)

2. Run the following commands: (You may have to replace `py` with `python` or
   `python3`)

```bash
git clone https://github.com/fieryhenry/TBCMailServer.git
pip install -e TBCMailServer/
py -m TBCMailServer
```

If you want to use the tool again all you need to do is run the `py -m tbcms` command

Then if you want the latest changes you only need to run `git pull` in the downloaded
`TBCMailServer` folder. (use `cd` to change the folder)

## Usage

1. Run `python -m tbcms` or `py -m tbcms` depending on
    your system.

1. Run `python -m tbcms --help` for more information.

1. You can change the port using the `--port` option. e.g.
    `python -m tbcms --port 5000`

1. Read [jamesiotio's CITM](https://github.com/jamestiotio/CITM) on how to
    format the list of presents.

1. Create a file called `presents.json` somewhere and put your presents in it.

1. Run `python -m tbcms --presents path/to/presents.json` to start
    server.

Example presents.json

```json
[
    {
        "id": 1,
        "title": "Items",
        "body": "Test Body",
        "createdAt": 1688648392,
        "items": [
            {
                "itemId": 22,
                "itemCategory": 0,
                "amount": 50,
                "title": "Catfood"
            },
            {
                "itemId": 29,
                "itemCategory": 0,
                "amount": 5,
                "title": "Platinum Ticket"
            }
        ]
    }
]
```

## Alternative Method

You can also change the public key the game uses to verify the server responses
to your own public key from a key pair you generated.

You can modify the `assets/nyanko-service-prd.pem` file in the APK to use your own
public key. You can generate a key pair using openssl:

```sh
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

The problem with this method is that you now need to intercept or use a private
server for every single request that uses the public key as now the game will
reject the official server responses from PONOS.

However, I did still manage to do all of that, but the game refused to upload
the save data to the game servers. It does a request to an aws server but it
aborts immediately after. I couldn't have changed the url of the server it
uploads to to my own server because the url is from a response of another
request with a signature that I don't know how to generate.

Another problem is that if you have a request with more than one slash in the
same place, serveo.net will respond with a 301 Moved Permanently and redirect to
the url with only one slash. But if the original request was a POST request,
the method will change to GET and break the request. If it instead used a 308
Permanent Redirect then it would keep the method as POST and it would work.
When downloading save data, PONOS accidentally has 2 slashes in the same place.
I don't know how to fix this.

I know that this is not a Flask issue because Flask responds correctly with a
308 Permanent Redirect. I think it is a problem with serveo.net.

It's probably possible to do this method but I can't be bothered to do it.

Even though this alternative method is not effective, I spent a lot of time on it
so I wanted to include it here.
