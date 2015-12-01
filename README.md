Just some random scripts that I use for the MITM proxy

## selectors.py
Used to find keywords in HTTP traffic.

```
mitmdump -s 'selectors.py -r -p -j selectors.json -a mitm_test'
```
