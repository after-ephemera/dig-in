typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

void print_bytes(unsigned char *bytes, int byteslen);
void canonicalize_name(char *name);
int name_ascii_to_wire(char *name, unsigned char *wire);
char *name_ascii_from_wire(unsigned char *wire, int *indexp);
dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only);
int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only);
