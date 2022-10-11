#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "types.h"
#include "utils.h"

// Can the raw socket receive partial ethernet frames?

//  +---------------+ 0
//  | dst MAC addr  |
//  +---------------+ 6
//  | src MAC addr  |
//  +---------------+ 12
//  | payload type  |
//  +---------------+ 14
//  | payload       |
//  | ...           |
//  | ...           |
//  +---------------+ ?
//  | CRC checksum  |
//  +---------------+

typedef struct {
    IPAddress IPWithUnknownMAC;
    void *userp;
    void (*callback)(void *userp, MACAddress MAC);
} PendingIPPacket;

typedef struct {
    PendingIPPacket *packets;
    size_t size, used;
} PendingIPPacketList;

void PendingIPPacketList_init(PendingIPPacketList *packetList)
{
    packetList->packets = NULL;
    packetList->size = 0;
    packetList->used = 0;
}

void PendingIPPacketList_free(PendingIPPacketList *packetList)
{
    free(packetList->packets);
}

bool PendingIPPacketList_append(PendingIPPacketList *packetList, IPAddress IP, 
                                void *userp, void (*callback)(void *userp, MACAddress MAC))
{
    if (packetList->packets == NULL || packetList->size == packetList->used) {

        size_t newSize;
        if (packetList->packets == NULL)
            newSize = 8;
        else
            newSize = 2 * packetList->size;

        assert(newSize > 0);

        void *temp = realloc(packetList->packets, newSize * sizeof(PendingIPPacket));
        if (temp == NULL)
            return false;

        packetList->packets = temp;
        packetList->size = newSize;
    }

    size_t k = packetList->used++;
    packetList->packets[k].IPWithUnknownMAC = IP;
    packetList->packets[k].callback = callback;
    packetList->packets[k].userp = userp;
    return true;
}

void PendingIPPacketList_resolve(PendingIPPacketList *packetList, MACAddress MAC, IPAddress IP)
{
    size_t resolved = 0;
    for (size_t i = 0; i < packetList->used; ++i)
        if (packetList->packets[i].IPWithUnknownMAC == IP) {
            packetList->packets[i].callback(packetList->packets[i].userp, MAC);
            resolved++;
        } else
            packetList->packets[i - resolved] = packetList->packets[i];
    packetList->used -= resolved;
    // TODO: Downsize the array?
}

typedef struct {
    MACAddress dst;
    MACAddress src;
    uint16_t proto;
} PACKED EthernetHeader;

typedef enum {
    ET_IPv4 = 0x800,
    ET_ARP  = 0x806,
    ET_IPv6 = 0x86DD,
} EtherType;

typedef enum {
    ARPOP_REQUEST = 1,
    ARPOP_REPLY = 2,
} ARPOperation;

typedef struct {
    EthernetHeader base;
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t  hardwareAddressSize;
    uint8_t  protocolAddressSize;
    uint16_t operation;
} PACKED ARPHeader;

typedef struct {
    ARPHeader base;
    MACAddress senderMAC;
    IPAddress  senderIP;
    MACAddress targetMAC;
    IPAddress  targetIP;
} PACKED ARPHeader_IPv4_MAC;

typedef struct {
    EthernetHeader base;
    uint8_t version: 4;
    uint8_t IHL: 4;
    uint8_t typeOfService: 6;
    uint8_t ECN: 2;
    uint16_t totalLength;
    uint16_t identifier;
    uint8_t flags: 3;
    uint16_t fragOffset: 13;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t checksum;
    IPAddress srcIP;
    IPAddress dstIP;
    /* .. options .. */
} PACKED IPHeader;


typedef struct {
    MACAddress *MACs;
    IPAddress  *IPs;
    size_t size, used;
} ARPTranslationTable;

bool ARPTranslationTable_insert(ARPTranslationTable *table, MACAddress MAC, IPAddress IP)
{
    if (table->MACs == NULL) {

        const size_t startSize = 8;
        void *mem = malloc((sizeof(MACAddress) + sizeof(IPAddress)) * startSize);
        if (mem == NULL)
            return false;

        table->MACs = mem;
        table->IPs  = (IPAddress*) (table->MACs + startSize);
        table->size = startSize;
        table->used = 0;

    } else if (table->size == table->used) {

        const size_t newSize = 2 * table->size;
        void *mem = malloc((sizeof(MACAddress) + sizeof(IPAddress)) * newSize);
        if (mem == NULL)
            return false;

        MACAddress *newMACs = mem;
        IPAddress  *newIPs  = (IPAddress*) (newMACs + newSize);

        for (size_t i = 0; i < table->used; ++i) {
            newMACs[i] = table->MACs[i];
            newIPs[i]  = table->IPs[i];
        }

        free(table->MACs);
        table->MACs = newMACs;
        table->IPs  = newIPs;
    }

    // We assume the MAC/IP pair isn't contained
    // already.
    table->MACs[table->used] = MAC;
    table->IPs[table->used] = IP;
    table->used++;
    return true;
}

int ARPTranslationTable_findIndexByIP(ARPTranslationTable *table, IPAddress address)
{
    for (size_t i = 0; i < table->used; ++i)
        if (table->IPs[i] == address)
            return (int) i;
    return -1;
}

bool ARPTranslationTable_getMACByIP(ARPTranslationTable *table, MACAddress *MAC, IPAddress IP)
{
    int i = ARPTranslationTable_findIndexByIP(table, IP);
    if (i < 0)
        return false;
    if (MAC != NULL)
        *MAC = table->MACs[i];
    return true;
}

bool ARPTranslationTable_updateIP(ARPTranslationTable *table, 
                                  MACAddress MAC, IPAddress IP)
{
    int i = ARPTranslationTable_findIndexByIP(table, IP);
    if (i < 0)
        return false;
    table->MACs[i] = MAC;
    return true;
}

static bool isARPIPv4OverEthernet(ARPHeader *packet)
{
    // This ARP implementation only supports IPv4
    // over ethernet.
    if (ntohs(packet->hardwareType) != 1)
        return false; // Not ethernet!
    if (ntohs(packet->protocolType) != 0x800)
        return false; // Not IPv4.

    // Redundant checks
    if (packet->hardwareAddressSize != sizeof(MACAddress))
        return false;
    if (packet->protocolAddressSize != sizeof(IPAddress))
        return false;
    return true;
}

static const char *getProtoName(uint16_t protoID)
{
    switch (protoID) {
        case ET_IPv4: return "IPv4";
        case ET_IPv6: return "IPv6";
        case ET_ARP: return "ARP";
    }
    return "???";
}

bool waitFrame(int socketDescriptor, int timeout)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(socketDescriptor, &rfds);

    struct timeval tv;
    tv.tv_sec  = timeout;
    tv.tv_usec = 0;
    int n = select(socketDescriptor+1, &rfds, NULL, NULL, &tv);
    if (n <= 0) {
        if (n < 0 && errno != EINTR)
            fprintf(stderr, "WARNING :: %s\n", strerror(errno));
        return false;
    }
    return true;
}

void printFrameHeader(EthernetHeader *header, FILE *stream)
{
    uint16_t proto = ntohs(header->proto);

    fprintf(stream, "Ethernet frame: { dst: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, "
                    "src: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, proto: %X (%s) }\n", 
                    header->dst.bytes[0], header->dst.bytes[1], header->dst.bytes[2],
                    header->dst.bytes[3], header->dst.bytes[4], header->dst.bytes[5],
                    header->src.bytes[0], header->src.bytes[1], header->src.bytes[2],
                    header->src.bytes[3], header->src.bytes[4], header->src.bytes[5],
                    proto, getProtoName(proto));
}

typedef struct {
    IPAddress  IP;
    MACAddress MAC;
    int deviceIndex;
    int socketDescriptor;
} Snack;

bool Snack_init(Snack *snack, const char *deviceName)
{
    if (deviceName == NULL)
        return false;

    int socketDescriptor = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socketDescriptor < 0) {
        reportError("%s\n", strerror(errno));
        return false;
    }

    if (setsockopt(socketDescriptor, SOL_SOCKET, SO_BINDTODEVICE, deviceName, strlen(deviceName))) {
        reportError("Failed to set socket option (%s)\n", strerror(errno));
        close(socketDescriptor);
        return false;
    }    

    struct ifreq ifr;
    strncpy(ifr.ifr_name, deviceName, IFNAMSIZ);

    if (ioctl(socketDescriptor, SIOCGIFHWADDR, &ifr)) {
        reportError("%s\n", strerror(errno));
        close(socketDescriptor);
        return -1;
    }
    // TODO: Make sure that ifr.ifr_hwaddr.sa_family refers to ethernet
    memcpy(&snack->MAC, ifr.ifr_hwaddr.sa_data, sizeof(MACAddress));

    if (ioctl(socketDescriptor, SIOCGIFINDEX, &ifr)) {
        reportError("%s\n", strerror(errno));
        close(socketDescriptor);
        return -1;
    }
    snack->deviceIndex = ifr.ifr_ifindex;

    if (ioctl(socketDescriptor, SIOCGIFADDR, &ifr)) {
        reportError("%s\n", strerror(errno));
        close(socketDescriptor);
        return -1;
    }
    snack->IP = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;
    
    snack->socketDescriptor = socketDescriptor;
    return true;
}

void Snack_free(Snack *snack)
{
    close(snack->socketDescriptor);
}

void printARPIPToMACPacket(ARPHeader_IPv4_MAC *packet)
{
    IPAddress senderIP = ntohl(packet->senderIP);
    IPAddress targetIP = ntohl(packet->targetIP);

    printf("ARP packet: {"
           " senderMAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,"
           " targetMAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X,"
           " senderIP: %d.%d.%d.%d,"
           " targetIP: %d.%d.%d.%d,"
           " operation: %s"
           " }\n",
           packet->senderMAC.bytes[0], packet->senderMAC.bytes[1],
           packet->senderMAC.bytes[2], packet->senderMAC.bytes[3],
           packet->senderMAC.bytes[4], packet->senderMAC.bytes[5],
           packet->targetMAC.bytes[0], packet->targetMAC.bytes[1],
           packet->targetMAC.bytes[2], packet->targetMAC.bytes[3],
           packet->targetMAC.bytes[4], packet->targetMAC.bytes[5],
           (senderIP >> 24) & 0xFF, (senderIP >> 16) & 0xFF,
           (senderIP >>  8) & 0xFF, (senderIP >>  0) & 0xFF,
           (targetIP >> 24) & 0xFF, (targetIP >> 16) & 0xFF,
           (targetIP >>  8) & 0xFF, (targetIP >>  0) & 0xFF,
           ntohs(packet->base.operation) == ARPOP_REQUEST ? "REQUEST" : "REPLY");
}

void buildARPResponseInPlace(Snack *snack, ARPHeader_IPv4_MAC *packet)
{
    packet->targetIP  = packet->senderIP;
    packet->targetMAC = packet->senderMAC;
    packet->senderIP  = snack->IP;
    packet->senderMAC = snack->MAC;
    packet->base.operation = htons(ARPOP_REPLY);
    packet->base.base.dst = packet->base.base.src;
    packet->base.base.src = snack->MAC;
}

bool sendUsingDevice(MACAddress MAC, int deviceIndex, 
                     int fd, const void *data, size_t size)
{
    struct sockaddr_ll deviceAddress;
    deviceAddress.sll_ifindex = deviceIndex;
    deviceAddress.sll_halen = 6; // Ethernet address length, which is 6.
    memcpy(deviceAddress.sll_addr, &MAC, 6);

    ssize_t result = sendto(fd, data, size, 0, 
                            (struct sockaddr*) &deviceAddress, 
                            sizeof(deviceAddress));
    return result >= 0;
}

static void handleARPPacket(Snack *snack, ARPTranslationTable *table,
                            PendingIPPacketList *pending, EthernetHeader *frame, 
                            size_t frameSize)
{
    assert(frame != NULL && ntohs(frame->proto) == ET_ARP);

    if (!isARPIPv4OverEthernet((ARPHeader*) frame))
        return;

    if (frameSize < sizeof(ARPHeader_IPv4_MAC))
        return;

    ARPHeader_IPv4_MAC *packet = (ARPHeader_IPv4_MAC*) frame;
    //printARPIPToMACPacket(packet);

    bool updated = ARPTranslationTable_updateIP(table, packet->senderMAC, packet->senderIP);

    if (packet->targetIP == snack->IP) {
    
        bool inserted = false;        
        if (!updated) {
            if (!ARPTranslationTable_insert(table, packet->senderMAC, packet->senderIP))
                fprintf(stderr, "WARNING :: Couldn't update translation table\n");
            else
                inserted = true;
        }
        
        if (packet->base.operation == htons(ARPOP_REQUEST)) {
            buildARPResponseInPlace(snack, packet);
            if (!sendUsingDevice(snack->MAC, snack->deviceIndex, 
                                 snack->socketDescriptor, frame, frameSize))
                reportError("Failed to send ARP reply (%s)\n", strerror(errno));
        }

        if (inserted)
            PendingIPPacketList_resolve(pending, packet->senderMAC, packet->senderIP);
    }
}

static void handleIPv4Packet(Snack *snack, ARPTranslationTable *table,
                             PendingIPPacketList *pending, EthernetHeader *frame, 
                             size_t frameSize)
{
    assert(frame != NULL && frame->proto == htons(ET_IPv4));

    if (frameSize < sizeof(IPHeader))
        return;

    IPHeader *packet = (IPHeader*) frame;

    /*
    if (snack->IP == packet->dstIP) {
        // f-for m-m-me?? uwu >w<
        ARPTranslationTable_getMACByIP();
    }
    */
    fprintf(stderr, "IP packet size: %d\n", packet->totalLength);
}

static bool sniffin = true;
static void sigFunc(int signo)
{
    if (signo == SIGINT)
        sniffin = false;
}

int main(void)
{
    if (signal(SIGINT, sigFunc) == SIG_ERR)
        fprintf(stderr, "WARNING :: Can't catch SIGINT\n");

    Snack snack;
    if (!Snack_init(&snack, "wlp2s0"))
        return -1;

    const size_t startSize = 65536;
    char *buffer = malloc(startSize);
    if (buffer == NULL) {
        reportError("No memory\n");
        Snack_free(&snack);
        return -1;
    }

    ARPTranslationTable table;
    memset(&table, 0, sizeof(ARPTranslationTable));

    PendingIPPacketList pending;
    PendingIPPacketList_init(&pending);

    while (sniffin) {

        if (!waitFrame(snack.socketDescriptor, 1000))
            continue;

        struct sockaddr_in socketAddress;
        socklen_t socketAddressLength = sizeof(socketAddress);
        ssize_t len = recvfrom(snack.socketDescriptor, buffer, startSize, 
                               0, (struct sockaddr*) &socketAddress, 
                               &socketAddressLength);
        if (len < 0) {
            reportError("%s\n", strerror(errno));
            free(buffer);
            Snack_free(&snack);
            return -1;
        }
        assert(len != 0);

        if (len < (ssize_t) sizeof(EthernetHeader)) {
            reportError("Invalid frame\n");
            sniffin = false;
        } else {
            EthernetHeader *header = (EthernetHeader*) buffer;
            printFrameHeader(header, stdout);
            switch (ntohs(header->proto)) {
                case ET_ARP:  handleARPPacket(&snack, &table, &pending, header, len); break;
                case ET_IPv4: handleIPv4Packet(&snack, &table, &pending, header, len); break;
                case ET_IPv6:break;
            }
        }
    }

    free(buffer);
    Snack_free(&snack);
    PendingIPPacketList_free(&pending);
    return 0;
}