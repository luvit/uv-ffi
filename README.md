# uv-ffi

Pure luajit-ffi bindings to libuv just for fun!

This is an experiment with using libuv directly from stock luajit.

## Install deps

On a recent ubuntu (Tested on 19.04), simply run:

```sh
sudo apt install luajit libuv1-dev
```

There is no need for luvit, luvi, or even the luv rocks package.

## Run the sample

Run the sample with luajit.

```sh
luajit test.lua
```
