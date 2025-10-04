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

import os
import gc
import RNS
import time
import math
import struct
import inspect
import threading
from time import sleep
from .vendor import umsgpack as umsgpack

class Transport:
    """
    Through static methods of this class you can interact with the
    Transport system of Reticulum.
    """
    # Constants
    BROADCAST                   = 0x00;
    TRANSPORT                   = 0x01;
    RELAY                       = 0x02;
    TUNNEL                      = 0x03;
    types                       = [BROADCAST, TRANSPORT, RELAY, TUNNEL]

    REACHABILITY_UNREACHABLE    = 0x00
    REACHABILITY_DIRECT         = 0x01
    REACHABILITY_TRANSPORT      = 0x02

    APP_NAME = "rnstransport"

    PATHFINDER_M                = 128       # Max hops
    """
    Maximum amount of hops that Reticulum will transport a packet.
    """
    
    PATHFINDER_R                = 1            # Retransmit retries
    PATHFINDER_G                = 5            # Retry grace period
    PATHFINDER_RW               = 0.5          # Random window for announce rebroadcast
    PATHFINDER_E                = 60*60*24*7   # Path expiration of one week
    AP_PATH_TIME                = 60*60*24     # Path expiration of one day for Access Point paths
    ROAMING_PATH_TIME           = 60*60*6      # Path expiration of 6 hours for Roaming paths

    # TODO: Calculate an optimal number for this in
    # various situations
    LOCAL_REBROADCASTS_MAX      = 2            # How many local rebroadcasts of an announce is allowed

    PATH_REQUEST_TIMEOUT        = 15           # Default timeout for client path requests in seconds
    PATH_REQUEST_GRACE          = 0.4          # Grace time before a path announcement is made, allows directly reachable peers to respond first
    PATH_REQUEST_RG             = 1.5          # Extra grace time for roaming-mode interfaces to allow more suitable peers to respond first
    PATH_REQUEST_MI             = 20           # Minimum interval in seconds for automated path requests

    STATE_UNKNOWN               = 0x00
    STATE_UNRESPONSIVE          = 0x01
    STATE_RESPONSIVE            = 0x02

    LINK_TIMEOUT                = RNS.Link.STALE_TIME * 1.25
    REVERSE_TIMEOUT             = 8*60         # Reverse table entries are removed after 8 minutes
    DESTINATION_TIMEOUT         = 60*60*24*7   # Destination table entries are removed if unused for one week
    MAX_RECEIPTS                = 1024         # Maximum number of receipts to keep track of
    MAX_RATE_TIMESTAMPS         = 16           # Maximum number of announce timestamps to keep per destination
    PERSIST_RANDOM_BLOBS        = 32           # Maximum number of random blobs per destination to persist to disk
    MAX_RANDOM_BLOBS            = 64           # Maximum number of random blobs per destination to keep in memory

    start_time                  = None
    jobs_locked                 = False
    jobs_running                = False
    job_interval                = 0.250
    links_last_checked          = 0.0
    links_check_interval        = 1.0
    receipts_last_checked       = 0.0
    receipts_check_interval     = 1.0
    announces_last_checked      = 0.0
    announces_check_interval    = 1.0
    pending_prs_last_checked    = 0.0
    pending_prs_check_interval  = 30.0
    cache_last_cleaned          = 0.0
    cache_clean_interval        = 300.0
    hashlist_maxsize            = 1000000
    tables_last_culled          = 0.0
    tables_cull_interval        = 5.0
    interface_last_jobs         = 0.0
    interface_jobs_interval     = 5.0

    traffic_rxb                 = 0
    traffic_txb                 = 0
    speed_rx                    = 0
    speed_tx                    = 0
    traffic_captured            = None

    identity = None


# Table entry indices

# Transport.path_table entry indices
IDX_PT_TIMESTAMP = 0
IDX_PT_NEXT_HOP  = 1
IDX_PT_HOPS      = 2
IDX_PT_EXPIRES   = 3
IDX_PT_RANDBLOBS = 4
IDX_PT_RVCD_IF   = 5
IDX_PT_PACKET    = 6

# Transport.reverse_table entry indices
IDX_RT_RCVD_IF   = 0
IDX_RT_OUTB_IF   = 1
IDX_RT_TIMESTAMP = 2

# Transport.announce_table entry indices
IDX_AT_TIMESTAMP = 0
IDX_AT_RTRNS_TMO = 1
IDX_AT_RETRIES   = 2
IDX_AT_RCVD_IF   = 3
IDX_AT_HOPS      = 4
IDX_AT_PACKET    = 5
IDX_AT_LCL_RBRD  = 6
IDX_AT_BLCK_RBRD = 7
IDX_AT_ATTCHD_IF = 8

# Transport.link_table entry indices
IDX_LT_TIMESTAMP = 0
IDX_LT_NH_TRID   = 1
IDX_LT_NH_IF     = 2
IDX_LT_REM_HOPS  = 3
IDX_LT_RCVD_IF   = 4
IDX_LT_HOPS      = 5
IDX_LT_DSTHASH   = 6
IDX_LT_VALIDATED = 7
IDX_LT_PROOF_TMO = 8

# Transport.tunnels entry indices
IDX_TT_TUNNEL_ID = 0
IDX_TT_IF        = 1
IDX_TT_PATHS     = 2
IDX_TT_EXPIRES   = 3