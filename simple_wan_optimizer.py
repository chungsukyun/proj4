import wan_optimizer
import utils
import tcp_packet

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.block_buffers = {}
        self.hash_to_payload = {}
        return

    def buffer_size(self, packet):
        size = 0;
        for p in self.block_buffers[packet.dest]:
            size += p.size()
        return size

    def sender(self, packet, address):
        size = self.buffer_size(packet)
        if size >= WanOptimizer.BLOCK_SIZE and not packet.is_fin:
            payload = ""
            for p in self.block_buffers[packet.dest]:
                payload += p.payload
            extra = payload[WanOptimizer.BLOCK_SIZE:]
            payload = payload[:WanOptimizer.BLOCK_SIZE]
            special = payload[(size - packet.size()):WanOptimizer.BLOCK_SIZE]
            h = utils.get_hash(payload)
            if h in self.hash_to_payload:
                hash_packet = tcp_packet.Packet(packet.src, packet.dest, False, False, h)
                self.send(hash_packet, address)
            else:
                self.hash_to_payload[h] = payload
                for i in range(len(self.block_buffers[packet.dest]) - 1):
                    self.send(self.block_buffers[packet.dest][i], address)
                special_packet = tcp_packet.Packet(packet.src, packet.dest, True, False, special)
                self.send(special_packet, address)
            if size == WanOptimizer.BLOCK_SIZE:
                self.block_buffers[packet.dest] = []
            else:
                remaining_packet = tcp_packet.Packet(packet.src, packet.dest, packet.is_raw_data, packet.is_fin, extra)
                self.block_buffers[packet.dest] = [remaining_packet]
        elif size < WanOptimizer.BLOCK_SIZE and packet.is_fin:
            payload = ""
            for p in self.block_buffers[packet.dest]:
                payload += p.payload
            h = utils.get_hash(payload)
            if h in self.hash_to_payload:
                hash_packet = tcp_packet.Packet(packet.src, packet.dest, False, True, h)
                self.send(hash_packet, address)
            else:
                self.hash_to_payload[h] = payload
                for p in self.block_buffers[packet.dest]:
                    self.send(p, address)
            self.block_buffers[packet.dest] = []
        elif size >= WanOptimizer.BLOCK_SIZE and packet.is_fin:
            payload = ""
            for p in self.block_buffers[packet.dest]:
                payload += p.payload
            extra = payload[WanOptimizer.BLOCK_SIZE:]
            payload = payload[:WanOptimizer.BLOCK_SIZE]
            special = payload[(size - packet.size()):WanOptimizer.BLOCK_SIZE]
            h = utils.get_hash(payload)
            e = utils.get_hash(extra)
            if h in self.hash_to_payload:
                hash_packet = tcp_packet.Packet(packet.src, packet.dest, False, False, h)
                self.send(hash_packet, address)
            else:
                self.hash_to_payload[h] = payload
                for i in range(len(self.block_buffers[packet.dest]) - 1):
                    self.send(self.block_buffers[packet.dest][i], address)
                special_packet = tcp_packet.Packet(packet.src, packet.dest, True, False, special)
                self.send(special_packet, address)
            if e in self.hash_to_payload:
                hash_packet = tcp_packet.Packet(packet.src, packet.dest, False, True, e)
                self.send(hash_packet, address)
            else:
                self.hash_to_payload[e] = extra
                extra_packet = tcp_packet.Packet(packet.src, packet.dest, True, True, e)
            self.block_buffers[packet.dest] = []

    def payload_sender(self, payload, packet, port):
        while len(payload) > utils.MAX_PACKET_SIZE:
            packet_payload = payload[:utils.MAX_PACKET_SIZE]
            new_packet = tcp_packet.Packet(packet.src, packet.dest, True, False, packet_payload)
            self.send(new_packet, port)
            payload = payload[utils.MAX_PACKET_SIZE:]
        new_packet = tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, payload)
        self.send(new_packet, port)

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of 
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            if not packet.is_raw_data:
                payload = self.hash_to_payload[packet.payload]
                self.payload_sender(payload, packet, self.address_to_port[packet.dest])
            else:
                if packet.dest not in self.block_buffers:
                    self.block_buffers[packet.dest] = [packet]
                else:
                    self.block_buffers[packet.dest] += [packet]
                self.sender(packet, self.address_to_port[packet.dest])
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            if packet.dest not in self.block_buffers:
                self.block_buffers[packet.dest] = [packet]
            else:
                self.block_buffers[packet.dest] += [packet]
            self.sender(packet, self.wan_port)
