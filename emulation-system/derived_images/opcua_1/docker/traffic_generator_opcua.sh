#!/bin/bash
while [ 1 ]
do
    # Simulate SSH connection 
    sleep 2
    timeout 5 sshpass -p 'testcsleuser' ssh -oStrictHostKeyChecking=no 172.18.8.21 > /dev/null 2>&1
    
    # OPC UA Browse Nodes
    sleep 2
    timeout 5 python3 -c "
from asyncua import Client
import asyncio

async def main():
    url = 'opc.tcp://172.18.8.21:4840/freeopcua/server/'
    async with Client(url) as client:
        root = client.get_root_node()
        await root.get_children()

asyncio.run(main())
" > /dev/null 2>&1
    
    # OPC UA Read Variable
    sleep 2
    timeout 5 python3 -c "
from asyncua import Client
import asyncio

async def main():
    url = 'opc.tcp://172.18.8.21:4840/freeopcua/server/'
    async with Client(url) as client:
        obj = await client.nodes.root.get_child(['0:Objects', 'ns=2:MyObject'])
        var = await obj.get_child('ns=2:MyVariable')
        await var.read_value()

asyncio.run(main())
" > /dev/null 2>&1
    
    # OPC UA Write Variable
    sleep 2
    timeout 5 python3 -c "
from asyncua import Client
import asyncio

async def main():
    url = 'opc.tcp://172.18.8.21:4840/freeopcua/server/'
    async with Client(url) as client:
        obj = await client.nodes.root.get_child(['0:Objects', 'ns=2:MyObject'])
        var = await obj.get_child('ns=2:MyVariable')
        await var.write_value(10.5)

asyncio.run(main())
" > /dev/null 2>&1
    
    sleep 2
done