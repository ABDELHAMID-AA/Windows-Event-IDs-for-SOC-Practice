
# INTRO

Hello, this time I'm going to try to set up an environment to practice a
SIEM tool (Splunk), which is important in the daily work of a SOC
analyst. Anyway, let's go step by step and everything will become clear.

------------------------------------------------------------------------

# SETTING UP THE ENVIRONMENT

In this lab, I'm going to use my machine (Windows 11) + VMware to create
2 virtual machines (Windows 10) + Tailscale VPN and, of course, Splunk
Enterprise and Splunk Universal Forwarder.

The architecture of the lab will be as follows:

                      +---------------------------------------+
                      |  MY MACHINE (Admin PC)                |
                      |      Splunk Enterprise Server         |
                      |    (Indexer + Search Head Role)       |
                      +-----------------------+---------------+
                                              |
                                      (Tailscale VPN)
                                              |
             ------------------------------------------------------------------
    (Tailscale VPN)                                                      (Tailscale VPN)
             |                                                                |
             |                                                                |
             |                                                                |
     Splunk Universal Forwarder                                    Splunk Universal Forwarder
             |                                                                |
             |                                                                |      
    +---------------------+                               +-----------------------------+
    | Windows Endpoint 1  |                               | Windows Endpoint 2          |
    |   - Event Logs      |                               |   - Event Logs              |
    |                     |                               |                             |
    +----------+----------+                               +--------------+--------------+

------------------------------------------------------------------------

So now let's proceed and install what we need.

------------------------------------------------------------------------

## ⇒ Installing Splunk Server

1.  *\[screenshot of the download\]*

Now let's wait for it to complete downloading, and after that, we will
install it.

2.  *\[screenshots of installing\]*

After completing the installation, let's test if it works well. Let's
open **localhost:8000** in the browser and see what we get.

3.  *\[screenshot of localhost on the browser\]*

After setting up the Splunk server, let's move on to the next step.

------------------------------------------------------------------------

## ⇒ Installing Tailscale for the Server and the Endpoints

After downloading Tailscale, install it on the server and on the
endpoints.

On the server:

4.  *\[screenshot of the server connection\]*

Now let's generate 2 auth keys to connect the endpoints.

5.  *\[screenshot of auth keys\]*

On Endpoint 1:

6.  *\[screenshot of endpoint 1 setting up\]*\
7.  *\[screenshot of status\]*

We do the same thing for the other endpoint.

------------------------------------------------------------------------

## ⇒ Installing Splunk Universal Forwarder

Now, after we put the server and the endpoints in the same network,
let's install the Universal Forwarders.

We will do the same steps on both endpoints:

After downloading UF, let's install it and configure the information to
connect to the Deployment Server and the Indexer.

8.  *\[screenshots of configuring it\]*\
9.  *\[same\]*

------------------------------------------------------------------------

Now after we finished, let's go back to the server machine and enable
listening on port **8089** and **9997**, because in this lab the Indexer
and the Deployment Server are running on the same machine.

Open CMD as Administrator and run these commands:

``` cmd
netsh advfirewall firewall add rule name="for Indexer" dir=in action=allow protocol=TCP localport=9997

netsh advfirewall firewall add rule name="for deployment server" dir=in action=allow protocol=TCP localport=9997
```

Now on the endpoints, let's enable forwarding:

``` cmd
netsh advfirewall firewall add rule name="to the indexer" dir=out action=allow protocol=TCP remoteport=9997

netsh advfirewall firewall add rule name="to the DS" dir=out action=allow protocol=TCP remoteport=8089
```

------------------------------------------------------------------------

## Why We Used TCP and Ports 9997 and 8089

**Port 9997:**\
This port is used by the Splunk Indexer to receive data from Universal
Forwarders. TCP is chosen because it ensures reliable delivery of log
data, meaning no events are lost during transmission between the
endpoints and the server.

**Port 8089 (TCP):**\
This port is used by the Splunk Deployment Server to communicate with
Universal Forwarders for configuration updates and app deployment.
Again, TCP ensures that all configuration messages are reliably sent and
received.

------------------------------------------------------------------------

Everything should now be working perfectly, so let's check.

After logging in to the Splunk Search Head, we have:

10. *\[screenshot of the forwarders working\]*

The screenshot above shows the two Universal Forwarders from the Windows
endpoints successfully connected to the Splunk server. This confirms
that the lab environment is properly set up, and the endpoints are ready
to forward logs to the Splunk Indexer.

That's all for this report.
