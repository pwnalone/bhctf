# Holy Hell

In this challenge, we are asked to retrieve information on VIN `1337`, and are directed to a web
application, hosted at [celsius.blockharbor.io:5800](http://celsius.blockharbor.io:5800/), where we
can generate VIN numbers and look up vehicle information by VIN number.

> Can you retreive info about the following VIN: 1337. If so, let us know, we want to know about
> that vehicle!

![VIN Lookup with Valid Signature](vin-lookup-valid.png)

Looking at the page source, we find the following JavaScript, embedded between `<script>` tags,
which enables the client to interact with the web application. We can see references to two API
endpoints, `/vin/register` and `/vin/info`, which are used to generate and look up VIN numbers,
respectively.

```js
$(document).ready(function() {
    $('#vinForm').submit(function(event) {
        event.preventDefault();
        var vin = $('#vinInput').val();
        lookupVIN(vin);
    });
});

function lookupVIN(vin) {
    var url = '/vin/info?vin=' + encodeURIComponent(vin);
    $.ajax({
        url: url,
        type: 'GET',
        success: function(response) {
            $('#result').html(response);
        },
        error: function(xhr, status, error) {
            $('#result').html('Error: ' + error);
        }
    });
}

function registerVIN() {
    $.ajax({
        url: '/vin/register',
        type: 'GET',
        success: function(response) {
            var vinValue = response.split('=')[1];
            <!-- lol raw write to the dom -->
            $('#vinInput').val(vinValue);
            $('#result').html('');

            var cookieHeader = xhr.getResponseHeader('Set-Cookie');
            if (cookieHeader) {
                var cookieParts = cookieHeader.split(';');
                var cookie = cookieParts[0];
                document.cookie = cookie;
            }
        },
        error: function(xhr, status, error) {
            $('#result').html('Error: ' + error);
        }
    });
}
```

When clicking the _Generate_ button, we observe that an HTTP GET request is sent to `/vin/register`,
and, in the response, we receive the VIN number and a Cookie containing a signature for the given
VIN. Attempts to look up vehicle information with an incorrect signature for a particular VIN,
results in an error.

![VIN Lookup with Invalid Signature](vin-lookup-invalid.png)

We can guess that the signatures might be generated in an insecure manner, which could allow us to
create a valid signature for our target VIN, but without having access to the source code, we'd be
flying blind. We can use [gobuster](https://www.kali.org/tools/gobuster/) or one of its many
alternatives to search for other directories and resources exposed by the web app.

```
gobuster -u http://celsius.blockharbor.io:5800/ -w /usr/share/wordlists/dirb/wordlists/small.txt -t 1 --delay 200ms
```

In the above command, we specify the `-t 1 --delay 200ms` options to make sure that we respect Block
Harbor's rate limit of 5 requests per second. Because I chose a fairly small wordlist (~950 lines),
the command shouldn't take too long to complete. Once it does, you'll see that it found a single
additional endpoint, `/app`, which appears to contain the source code for the web app. Let's
download the file from the server using `wget` and save it as a Python script.

```
wget http://celsius.blockharbor.io:5800/app -O app.py
```

Taking a look at the source code, we see that an insecure signature sheme is, indeed, being used.
The signature algorithm simply computes the SHA-256 digest of the input data, prefixed with a random
128-bit key. MD5, SHA-1, and most of SHA-2 (including SHA-256) are susceptible to a [length
extension attack](https://en.wikipedia.org/wiki/Length_extension_attack) if used when constructing
message authentication codes (MACs). Given any signed input, this attack allows one to compute a
valid signature for the same input with some extra data appended to it. The fact that we don't know
the value of the secret data is irrelevant, since the server will prepend it to the input for us.

```py
_SECURE_BYTES = urandom(16)

def calc_sig(data):
    if type(data) != bytes:
        data = data.encode()
    md = sha256(_SECURE_BYTES + data)
    return md.hexdigest()
```

In our case, here, the input that gets hashed by the server's signature algorithm is the value of
the _entire_ query string that is sent in the HTTP GET request to `/vin/info`. So if we request
`/vin/info?vin=1FMBU01BX2R8SEDBJ`, the server will compute the SHA-256 digest of
`vin=1FMBU01BX2R8SEDBJ`, prefixed with the random key, and then check that it matches the signature
we sent in the HTTP Cookie header. If the signatures match, we get the information on that VIN,
otherwise, we get an error. Therefore, we want to compute the signature for the original query
string, `vin=1FMBU01BX2R8SEDBJ`, extended with `&vin=1337`, so that the web app, when converting the
query string to a dictionary, will overwrite the first VIN with the second one.

```py
def to_dct(data):
    _dct = {}
    try:
        data = data.split(b'&')
        for line in data:
            k,v = line.split(b'=')
            _dct[k] = v
    except Exception as e:
        pass
    return _dct
```

It's important to keep in mind that SHA-256 hashes data in 64-byte blocks, meaning that the input
will have to be padded to a multiple of 64 bytes before being processed. The padding scheme it uses
is not that complicated, but to avoid going into too much detail I'll just refer you to _Section
5.1 Padding the Message_ of [FIPS
180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), where you can read all about it.

To perform the length extension attack, we need to be able to manually set the internal state of the
SHA-256 hash function. Python's `hashlib` module, however, does not give the user such access. To
save ourselves the hassle of having to reinvent the wheel, we can use the 3rd party
[hlextend](https://github.com/stephenbradshaw/hlextend) module, which already implements the attack
for us. It's not available on PyPi as of writing this, but it has no external dependencies, so
using it is as simple as downloading the single-file Python module from the project's GitHub repo.

With the [helper script](extend.py) I wrote, we can enter a known signature, its corresponding VIN,
and our target VIN, and we will get a new query string along with its computed signature. All that's
left to do to get the flag is set the signature cookie to the new value and send the query string in
an HTTP GET request to the `/vin/info` endpoint.

```
$ python3 extend.py 518151fdc2b3d5a8beae3ddf0a4b0f4e5c32fdbc967bfc8963a7133ffc143470 1GTHC83G64B2F5VU8 1337

New Query = vin=1GTHC83G64B2F5VU8%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%28%26vin=1337
Signature = cac53476985c5d01a17feded0be21b923f057a36260dada19493aa4b70b68a1f
```

**Flag:** `bh{h4sh_ba$h_m1s_ma7ch}`
