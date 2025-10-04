This is a light implementation of reticulum, based on the [official python library](https://github.com/markqvist/Reticulum/).

This is a light "BYO" version that is compatable, but missing transport, interfaces, packet-callbacks, and file-use.

The essential idea is that is has the basics, and works the same, but no automatic-management of things. The hope is that it will be usable in constrained enviroments, like micropython, but still feel familiar.

Eventually you can just not use that stuff, but eventuallly I will strip it all out. For now, this is mostly a code-style thing, and you should be able to run all the same code in multiple pyhton runtimes & environments.
