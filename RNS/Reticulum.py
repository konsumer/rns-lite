# Reticulum License
#
# Copyright (c) 2016-2025 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .vendor.platformutils import get_platform

from RNS.vendor.configobj import ConfigObj
import configparser
import multiprocessing.connection
import importlib.util
import threading
import signal
import atexit
import struct
import array
import time
import os
import RNS

class Reticulum:
    """
    This class is used to initialise access to Reticulum within a
    program. You must create exactly one instance of this class before
    carrying out any other RNS operations, such as creating destinations
    or sending traffic. Every independently executed program must create
    their own instance of the Reticulum class, but Reticulum will
    automatically handle inter-program communication on the same system,
    and expose all connected programs to external interfaces as well.

    As soon as an instance of this class is created, Reticulum will start
    opening and configuring any hardware devices specified in the supplied
    configuration.

    Currently the first running instance must be kept running while other
    local instances are connected, as the first created instance will
    act as a master instance that directly communicates with external
    hardware such as modems, TNCs and radios. If a master instance is
    asked to exit, it will not exit until all client processes have
    terminated (unless killed forcibly).

    If you are running Reticulum on a system with several different
    programs that use RNS starting and terminating at different times,
    it will be advantageous to run a master RNS instance as a daemon for
    other programs to use on demand.
    """

    # Future minimum will probably be locked in at 251 bytes to support
    # networks with segments of different MTUs. Absolute minimum is 219.
    MTU            = 500
    """
    The MTU that Reticulum adheres to, and will expect other peers to
    adhere to. By default, the MTU is 500 bytes. In custom RNS network
    implementations, it is possible to change this value, but doing so will
    completely break compatibility with all other RNS networks. An identical
    MTU is a prerequisite for peers to communicate in the same network.

    Unless you really know what you are doing, the MTU should be left at
    the default value.
    """

    LINK_MTU_DISCOVERY   = True
    """
    Whether automatic link MTU discovery is enabled by default in this
    release. Link MTU discovery significantly increases throughput over
    fast links, but requires all intermediary hops to also support it.
    Support for this feature was added in RNS version 0.9.0. This option
    will become enabled by default in the near future. Please update your
    RNS instances.
    """

    MAX_QUEUED_ANNOUNCES = 16384
    QUEUED_ANNOUNCE_LIFE = 60*60*24

    ANNOUNCE_CAP = 2
    """
    The maximum percentage of interface bandwidth that, at any given time,
    may be used to propagate announces. If an announce was scheduled for
    broadcasting on an interface, but doing so would exceed the allowed
    bandwidth allocation, the announce will be queued for transmission
    when there is bandwidth available.

    Reticulum will always prioritise propagating announces with fewer
    hops, ensuring that distant, large networks with many peers on fast
    links don't overwhelm the capacity of smaller networks on slower
    mediums. If an announce remains queued for an extended amount of time,
    it will eventually be dropped.

    This value will be applied by default to all created interfaces,
    but it can be configured individually on a per-interface basis. In
    general, the global default setting should not be changed, and any
    alterations should be made on a per-interface basis instead.
    """

    MINIMUM_BITRATE = 5
    """
    Minimum bitrate required across a medium for Reticulum to be able
    to successfully establish links. Currently 5 bits per second.
    """

    # TODO: Let Reticulum somehow continously build a map of per-hop
    # latencies and use this map for global timeout calculation.
    DEFAULT_PER_HOP_TIMEOUT = 6

    # Length of truncated hashes in bits.
    TRUNCATED_HASHLENGTH = 128

    HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
    HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
    IFAC_MIN_SIZE    = 1
    IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
    
    MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE

    RESOURCE_CACHE   = 24*60*60
    JOB_INTERVAL     = 5*60
    CLEAN_INTERVAL   = 15*60
    PERSIST_INTERVAL = 60*60*12
    GRACIOUS_PERSIST_INTERVAL = 60*5

    router           = None
    config           = None
    
    # The default configuration path will be expanded to a directory
    # named ".reticulum" inside the current users home directory
    userdir          = os.path.expanduser("~")
    configdir        = None
    configpath       = ""
    storagepath      = ""
    cachepath        = ""
    interfacepath    = ""

    __instance       = None

    __interface_detach_ran = False
    __exit_handler_ran = False

