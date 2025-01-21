#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>

#define FIX_PADDING 1

void error(const char *msg) {
    perror(msg); exit(0);
}

int read_file(const char* filename, char* buffer) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    if (!buffer) return -1;
    fread(buffer, 1, size, file);
    fclose(file);
    return size;
}

int write_io(int sockfd, char* message, int length) {
    int sent = 0;
    do {
        int bytes = write(sockfd,message+sent,length-sent);
        if (bytes < 0)
            error("write failed");
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < length);
    return length;
}

int read_uint16(char* buffer, int offset) {
    int result = (buffer[offset] & 0xFF) << 8 | buffer[offset + 1] & 0xFF;
    return result;
}

int read_uint24(char* buffer, int offset) {
    int result = (buffer[offset] & 0xFF) << 16 | (buffer[offset + 1] & 0xFF) << 8 | buffer[offset + 2] & 0xFF;
    return result;
}

void write_uint16(char* buffer, int offset, int value) {
    buffer[offset++] = (value >> 8) & 0xFF;
    buffer[offset  ] = (value  & 0xFF);
}

void write_uint24(char* buffer, int offset, int value) {
    buffer[offset++] = (value >> 16) & 0xFF;
    buffer[offset++] = (value >> 8) & 0xFF;
    buffer[offset  ] = (value  & 0xFF);
}

int find_extensions_offset(char* buffer, int length) {
    int offset = 43;
    int session_id_length = buffer[offset];
    offset += session_id_length + 1;
    int cipher_suites_length = read_uint16(buffer, offset);
    offset += cipher_suites_length + 2;
    int compression_methods_length = buffer[offset];
    offset += compression_methods_length + 1;
    return offset;
}

int find_padding_extension_offset(char* buffer, int offset, int length) {
    offset += 2; //skip extension length
    do {
        int ext_type = read_uint16(buffer, offset);
        if (ext_type == 0x15) {
            return offset + 2;
        } else {
            int ext_len = read_uint16(buffer, offset + 2);
            offset += ext_len + 4;
        }
    } while(offset < length);
    return -1;
}

int main(int argc,char *argv[])
{
    int tls_1_length, tls_2_length;
    char tls_1[2048], tls_2[2048];
    tls_1_length = read_file("tls_clienthello_www_google_com.bin", tls_1);
    if (tls_1_length == -1) {
        error("read_file failed");
    }
    tls_2_length = read_file("hidden_data", tls_2);
    if (tls_2_length == -1) {
        error("read_file failed");
    }
    int portno =        443;
    char *host =        "www.google.com";
    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("sockfd failed");
    server = gethostbyname(host);
    if (server == NULL) error("gethostbyname failed");
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
        error("connect failed");
    int flag = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) < 0) {
        error("setsockopt failed");
    }
    int res;

    //fix record length
    int tls_1_record_pos = 3;
    int tls_1_record_size = read_uint16(tls_1, tls_1_record_pos);
    tls_1_record_size += tls_2_length;
    write_uint16(tls_1, tls_1_record_pos, tls_1_record_size);

    //fix handhsake length
    int tls_1_handshake_pos = 6;
    int tls_1_handshake_size = read_uint24(tls_1, tls_1_handshake_pos);
    tls_1_handshake_size += tls_2_length;
    write_uint24(tls_1, tls_1_handshake_pos, tls_1_handshake_size);

    //fix extensions length
    int tls_1_extensions_pos = find_extensions_offset(tls_1, tls_1_length);
    if (tls_1_extensions_pos < 0) {
        error("find_extensions_offset failed");
    }
    int tls_1_extensions_length = read_uint16(tls_1, tls_1_extensions_pos);
    tls_1_extensions_length += tls_2_length;
    write_uint16(tls_1, tls_1_extensions_pos, tls_1_extensions_length);

    //fix padding extension length
    if (FIX_PADDING) {
        int tls_1_padding_pos = find_padding_extension_offset(tls_1, tls_1_extensions_pos, tls_1_length);
        if (tls_1_padding_pos < 0) {
            printf("find_padding_extension_offset failed\n");
            printf("trying to add padding extension\n");
            tls_1_extensions_length += 4;                                       // type (uint16) + length (uint16)
            write_uint16(tls_1, tls_1_extensions_pos, tls_1_extensions_length); // fix extensions length again
            tls_1_record_size += 4;                                             // type (uint16) + length (uint16)
            write_uint16(tls_1, tls_1_record_pos, tls_1_record_size);           // fix record size
            tls_1_handshake_size += 4;                                          // type (uint16) + length (uint16)
            write_uint24(tls_1, tls_1_handshake_pos, tls_1_handshake_size);     // fix handshake size
            write_uint16(tls_1, tls_1_length, 0x15);                            // add padding extension
            write_uint16(tls_1, tls_1_length + 2, 0x00);                        // set padding length at 0
            tls_1_padding_pos = tls_1_length + 2;                               // skip padding type field
            tls_1_length += 4;                                                  // increase packet size
        }
        int tls_1_padding_length = read_uint16(tls_1, tls_1_padding_pos);
        tls_1_padding_length += tls_2_length;
        write_uint16(tls_1, tls_1_padding_pos, tls_1_padding_length);
    }

    //send packets
    res = write_io(sockfd, tls_1, tls_1_length);
    if (res == -1) {
        error("write_io was failed");
    }
    res = write_io(sockfd, tls_2, tls_2_length);
    if (res == -1) {
        error("write_io was failed");
    }
    close(sockfd);
    return 0;
}
