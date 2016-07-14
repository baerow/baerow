#include <pcap.h>
    #include <stdio.h>

    int main()
    {
       pcap_t *handle;         /* Session handle */
       char *dev;         /* The device to sniff on */
       char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
       struct bpf_program fp;      /* The compiled filter */
       char filter_exp[] = "port 80";   /* The filter expression */
       bpf_u_int32 mask;      /* Our netmask */
       bpf_u_int32 net;      /* Our IP */

       /* Define the device */
       dev = pcap_lookupdev(errbuf);
       if (dev == NULL) {
           fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
           return(2);
       }
       /* Find the properties for the device */
       if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
           fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
           net = 0;
           mask = 0;
       }
       /* Open the session in promiscuous mode */
       handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
       if (handle == NULL) {
           fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
           return(2);
       }
       /* Compile and apply the filter */
       if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
           fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       if (pcap_setfilter(handle, &fp) == -1) {
           fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       /* Grab a packet */
       while(1){
           struct pcap_pkthdr * hdr;
           const u_char * packet;
           const int res = pcap_next_ex(handle, &hdr, &packet);
           if(res<0)
               break;
           if(res==0)
               continue;


           printf("DST MAC : %x:%x:%x:%x:%x:%x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
           printf("SRC MAC : %x:%x:%x:%x:%x:%x\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
           printf("SRC IP : %d.%d.%d.%d\n",packet[26],packet[27],packet[28],packet[29]);
           printf("SRC IP : %d.%d.%d.%d\n",packet[30],packet[31],packet[32],packet[33]);
           printf("SRC PORT : %d\n",packet[34,35]);
           printf("DST PORT : %d\n",packet[36,37]);
           /* Print its length */
           printf("[%d]\n", hdr->len);
       }
       /* And close the session */
       pcap_close(handle);
       return(0);
    }
