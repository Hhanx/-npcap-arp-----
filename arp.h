#pragma once
#include <iostream>
#include <pcap.h>
#include <cstring>
#include <winsock2.h>
#include <vector>
#pragma comment(lib, "ws2_32.lib")


// ��arp����������������ȡָ��������IP��MAC��ַ
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")


#include <thread>
#include <mutex>
#include <map>
#include <string>
#include <sstream>

#include <afxcmn.h>



#include <cstdlib>
#include <ctime>
#include <iomanip>




using namespace std;



// ARPͷ�ṹ
struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};

// ��̫��ͷ�ṹ
struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};



class arp
{
public:
	arp();
	~arp();

    void string_ip_to_uint8(const std::string& ip, uint8_t out[4]);

    bool macToUint8(const std::string& mac, uint8_t out[6]);

	vector<string> get_devices();
	
	pcap_t* get_handle(const string& device_name);
 
    int sendArp(uint8_t* src_ip, uint8_t* src_mac, uint8_t* dst_ip);

    // ���첢����ARP��Ӧ�����ظ������ߵ�MAC��ַ
    int sendMyMacArp(uint8_t* my_ip, uint8_t* my_mac, uint8_t* dst_ip, uint8_t* dst_mac);



    string recvArp(uint8_t src_ip[4], uint8_t dst_ip[4]);

    vector <string> recvArp_request();

    std::string generateRandomMacAddress() {
        // ��ʼ�����������
        static bool initialized = false;
        if (!initialized) {
            std::srand(std::time(nullptr));
            initialized = true;
        }

        unsigned char mac[6];

        // ����6������ֽ�
        // ��һ���ֽڵ����λ��Ϊ0��ȷ�����Ƕಥ��ַ
        mac[0] = (std::rand() % 0xFF) & 0xFE;

        // ��������5���ֽ�
        for (int i = 1; i < 6; ++i) {
            mac[i] = std::rand() % 0xFF;
        }

        // ת��Ϊ�ַ�����ʽ
        std::stringstream ss;
        for (int i = 0; i < 6; ++i) {
            if (i > 0) {
                ss << "-";
            }
            // ����λʮ��������������㲹0
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
        }

        // ת��Ϊ��д������
        std::string result = ss.str();
        for (char& c : result) {
            c = toupper(c);
        }

        return result;
    }

    pcap_t* get_handle_();

    bool get_device_ip_mac(const string& device_name, string& ip, string& mac);
    
    void scan_ip(const string& ip, const string& mac, int threadCount, CListCtrl* pListCtrl, BOOL* threadflag);

    //map<string, string> get_scan_results();

    void ShowError(string msg, const char* tishi);

    mutex results_mutex;

    map<string, string> scan_results;

    int ips_Count = 0;

    string device_name;



private:

    void arp_request(const string& target_ip, CListCtrl* pListCtrl);

    vector<string> get_ips_in_subnet(const string& ip);
   
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

    pcap_t *handle;

    pcap_if_t* alldevs;

    
};
