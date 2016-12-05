import wan_optimizer
import utils
import tcp_packet

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.block_buffers = {}
        self.hash_to_payload = {}
        return

    def sender(self, packet, port):
        string = self.block_buffers[packet.dest]
        i = len(string) - len(packet.payload) + 1
        if i == 1:
            i = 48
        while i < (len(string) + 1):
            window = string[(i-48):i]
            h = utils.get_hash(window)
            if utils.get_last_n_bits(h, 13) == WanOptimizer.GLOBAL_MATCH_BITSTRING:
                payload = self.block_buffers[packet.dest][:i]
                payload_hash = utils.get_hash(payload)
                if payload_hash in self.hash_to_payload:
                    hash_packet = tcp_packet.Packet(packet.src, packet.dest, False, packet.is_fin, payload_hash)
                    self.send(hash_packet, port)
                else:
                    if payload_hash == '\xbc\x17j\xea\x9a7ERJ\xe9\xd8\x01Jl\xb1\xb8\xa1\x88>}':
                        print payload
                    self.hash_to_payload[payload_hash] = payload
                    self.payload_sender(payload, packet, port)
                self.block_buffers[packet.dest] = self.block_buffers[packet.dest][i:]
                i += 48
            else:
                i += 1
        if packet.is_fin:
            payload = self.block_buffers[packet.dest]
            payload_hash = utils.get_hash(payload)
            if payload_hash not in self.hash_to_payload:
                self.hash_to_payload[payload_hash] = payload
            self.payload_sender(payload, packet, port)

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
        functionality described in part 2.  You are welcome to implement private
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
                    self.block_buffers[packet.dest] = packet.payload
                else:
                    self.block_buffers[packet.dest] += packet.payload
                self.sender(packet, self.address_to_port[packet.dest])
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            if packet.dest not in self.block_buffers:
                self.block_buffers[packet.dest] = packet.payload
            else:
                self.block_buffers[packet.dest] += packet.payload
            self.sender(packet, self.wan_port)
