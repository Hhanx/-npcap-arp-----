#include "arp.h"
#include <stdexcept>
#include <Windows.h>



arp::arp()
{
	//初始化WinSock
	this->handle = NULL;
	this->alldevs = NULL;
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		ShowError("WSAStartup failed.", "Error");
	}
}
arp::~arp()
{
	pcap_close(handle);
	pcap_freealldevs(alldevs);
	WSACleanup();
}
// 将字符串形式的IP地址转换为uint8_t数组形式
void arp::string_ip_to_uint8(const std::string& ip, uint8_t out[4])
{
	size_t start = 0, end = 0;
	for (int i = 0; i < 4; ++i) {
		end = ip.find('.', start);
		std::string part = (end == std::string::npos) ? ip.substr(start) : ip.substr(start, end - start);
		out[i] = static_cast<uint8_t>(std::stoi(part));
		start = end + 1;
	}
}

bool arp::macToUint8(const std::string& mac, uint8_t out[6]) {
	size_t start = 0;
	int index = 0;

	while (start < mac.size() && index < 6) {
		// 查找下一个冒号分隔符
		size_t end = mac.find('-', start);
		if (end == std::string::npos) {
			end = mac.find(':', start);
		}

		// 提取当前部分（最后一部分没有冒号）
		std::string part;
		if (end == std::string::npos) {
			part = mac.substr(start);
		}
		else {
			part = mac.substr(start, end - start);
		}

		// 检查每个部分是否合法（1-2个十六进制字符）
		if (part.empty() || part.size() > 2) {
			return false;
		}

		// 转换十六进制字符串为uint8_t
		try {
			std::stringstream ss;
			ss << std::hex << part;
			unsigned int val;
			ss >> val;
			if (val > 0xFF) {  // 确保值在0-255范围内
				return false;
			}
			out[index++] = static_cast<uint8_t>(val);
		}
		catch (...) {
			return false;  // 转换失败（如非十六进制字符）
		}

		// 移动到下一部分
		if (end == std::string::npos) {
			break;
		}
		start = end + 1;
	}

	// 确保正好解析了6个部分
	return index == 6;
}

// 获取所有网络设备列表
vector<string> arp::get_devices()
{
	vector<string> devices;

	// 获取网络设备列表
	if (pcap_findalldevs(&this->alldevs, errbuf) == -1) {
		ShowError("pcap_findalldevs error: " + string(errbuf), "Error");
		return {};
	}

	for (pcap_if_t* d = this->alldevs; d; d = d->next) {
		devices.push_back(d->description);
	}

	return devices;
}
//  获取指定设备的 pcap 句柄
pcap_t* arp::get_handle(const string& device_name)
{
	this->device_name = device_name;
	pcap_if_t* selected_dev = nullptr;

	for (pcap_if_t* d = this->alldevs; d; d = d->next) {
		if (device_name == d->description) {
			selected_dev = d;
			break;
		}
	}

	if (!selected_dev) {
		ShowError("No matching device found.", "Error");
		return NULL;
	}

	// 检查网卡状态
	if (selected_dev->flags & PCAP_IF_LOOPBACK) {
		ShowError("选中的设备是回环接口，无法发送ARP包。", "Error");
		return NULL;
	}
	if (!(selected_dev->flags & PCAP_IF_UP)) {
		ShowError("选中的设备未启用，无法发送ARP包。", "Error");
		return NULL;
	}

	handle = pcap_open_live(selected_dev->name, 65536, 1, 1000, errbuf);
	if (!handle) {
		ShowError("pcap_open_live error: ", "Error");
		return NULL;
	}


	return handle;
}
// 发送 ARP 请求
int arp::sendArp(uint8_t* src_ip, uint8_t* src_mac, uint8_t* dst_ip)
{

	uint8_t packet[42] = { 0 };
	eth_header* eth = (eth_header*)packet;
	arp_header* arp = (arp_header*)(packet + sizeof(eth_header));
	memset(eth->dst_mac, 0xFF, 6);
	memcpy(eth->src_mac, src_mac, 6);
	eth->eth_type = htons(0x0806);
	arp->htype = htons(1);
	arp->ptype = htons(0x0800);
	arp->hlen = 6;
	arp->plen = 4;
	arp->oper = htons(1);
	memcpy(arp->sha, src_mac, 6);
	memcpy(arp->spa, src_ip, 4);
	memset(arp->tha, 0x00, 6);
	memcpy(arp->tpa, dst_ip, 4);

	if (pcap_sendpacket(handle, packet, 42) != 0) {

		string errorstr = "";
		errorstr = "pcap_sendpacket error: ";
		errorstr += pcap_geterr(handle);
		errorstr += "请检查：\n";
		errorstr += "1. 网卡是否启用且已连接\n";
		errorstr += "2. 是否使用 npcap 驱动并勾选“支持发送原始包”\n";
		errorstr += "3. 是否用管理员权限运行\n";
		errorstr += "4. 防火墙/杀毒软件是否拦截\n";
		this->ShowError(errorstr, "Error");
	}



	return 0;
}

int arp::sendMyMacArp(uint8_t* my_ip, uint8_t* my_mac, uint8_t* dst_ip, uint8_t* dst_mac)
{
	// 构造ARP响应包
	uint8_t reply_pkt[42] = { 0 };
	eth_header* rep_eth = (eth_header*)reply_pkt;
	arp_header* rep_arp = (arp_header*)(reply_pkt + sizeof(eth_header));

	memcpy(rep_eth->dst_mac, dst_mac, 6); // 目标MAC为请求者MAC
	memcpy(rep_eth->src_mac, my_mac, 6);   // 源MAC为本机MAC
	rep_eth->eth_type = htons(0x0806);

	rep_arp->htype = htons(1);
	rep_arp->ptype = htons(0x0800);
	rep_arp->hlen = 6;
	rep_arp->plen = 4;
	rep_arp->oper = htons(2); // 响应

	memcpy(rep_arp->sha, my_mac, 6);      // 源MAC为本机MAC
	memcpy(rep_arp->spa, my_ip, 4);       // 源IP为本机IP
	memcpy(rep_arp->tha, dst_mac, 6);    // 目标MAC为请求者MAC
	memcpy(rep_arp->tpa, dst_ip, 4);    // 目标IP为请求者IP

	pcap_sendpacket(handle, reply_pkt, 42);
	return 0;
}

// 接收 ARP 响应
string arp::recvArp(uint8_t src_ip[4], uint8_t dst_ip[4]) {

	if (get_handle_() == nullptr) {
		ShowError("没有网卡", "Error");
		return "";
	}


	// 获取当前时间作为开始时间
	auto start_time = std::chrono::steady_clock::now();

	while (true) {
		// 检查是否超时（2秒）
		auto current_time = std::chrono::steady_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
		if (elapsed.count() >= 2000) { // 超过2秒
			break;
		}

		struct pcap_pkthdr* header;
		const u_char* pkt_data;
		int res = pcap_next_ex(handle, &header, &pkt_data);
		if (res == 0) continue; // 超时
		if (res < 0) break;     // 错误或文件结束

		eth_header* eth = (eth_header*)pkt_data;
		if (ntohs(eth->eth_type) != 0x0806) continue; // 不是ARP

		arp_header* arp = (arp_header*)(pkt_data + sizeof(eth_header));
		if (ntohs(arp->oper) != 2) continue; // 不是ARP响应



		if (memcmp(arp->spa, dst_ip, 4) == 0 && memcmp(arp->tpa, src_ip, 4) == 0) {
			char mac_str[18] = { 0 };
			snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
				arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);

			/*CString str_ip;
			str_ip.Format(L"%d.%d.%d.%d", arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);*/
			//CString str_mac(mac_str);
			//AfxMessageBox(str_ip + L"    " + str_mac);
			return mac_str;
		}


		/*char mac_str[18] = { 0 };
		snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
			arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);

		CString str_ip;
		str_ip.Format(L"%d.%d.%d.%d", arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
		CString str_mac(mac_str);
		AfxMessageBox(str_ip + L"    " + str_mac);*/
	}
	return "00:00:00:00:00:00";
}

vector<string> arp::recvArp_request()
{

	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int res = pcap_next_ex(handle, &header, &pkt_data);
	if (res == 0) return { "continue\0" }; // 超时
	if (res < 0) return { "break\0" };     // 错误或文件结束

	eth_header* eth = (eth_header*)pkt_data;
	if (ntohs(eth->eth_type) != 0x0806) return { "continue\0" }; // 不是ARP

	arp_header* arp = (arp_header*)(pkt_data + sizeof(eth_header));
	if (ntohs(arp->oper) != 1) return { "continue\0" }; // 不是ARP请求

	//源
	char mac_str[18] = { 0 };
	snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
		arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);

	char mac_ip[18] = { 0 };
	snprintf(mac_ip, sizeof(mac_ip), "%d.%d.%d.%d",
		arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);

	//目标
	char mac_ip_tap[18] = { 0 };
	snprintf(mac_ip_tap, sizeof(mac_ip_tap), "%d.%d.%d.%d",
		arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);

	char mac_str_tha[18] = { 0 };
	snprintf(mac_str_tha, sizeof(mac_str_tha), "%02X:%02X:%02X:%02X:%02X:%02X",
		arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);



	return { mac_ip , mac_str , mac_ip_tap, mac_str_tha };
}

// 获取当前的 pcap 句柄
pcap_t* arp::get_handle_()
{
	if (handle != NULL) return handle;
	return nullptr;
}
// 获取设备的 IP 和 MAC 地址
bool arp::get_device_ip_mac(const string& device_name, string& ip, string& mac)
{
	pcap_if_t* selected_dev = nullptr;
	for (pcap_if_t* d = this->alldevs; d; d = d->next) {
		if (device_name == d->description) {
			selected_dev = d;
			break;
		}
	}
	if (!selected_dev) return false;

	// 获取IP地址
	ip = "";
	for (pcap_addr_t* a = selected_dev->addresses; a; a = a->next) {
		if (a->addr && a->addr->sa_family == AF_INET) {
			sockaddr_in* sa = (sockaddr_in*)a->addr;
			ip = inet_ntoa(sa->sin_addr);
			break;
		}
	}

	// 获取MAC地址
	mac = "";
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD dwBufLen = sizeof(AdapterInfo);
	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
	if (dwStatus == ERROR_SUCCESS) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		while (pAdapterInfo) {
			if (strcmp(pAdapterInfo->Description, device_name.c_str()) == 0) {
				char macstr[32] = { 0 };
				for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
					sprintf(macstr + i * 3, "%02X%s", pAdapterInfo->Address[i], (i == pAdapterInfo->AddressLength - 1) ? "" : "-");
				}
				mac = macstr;
				break;
			}
			pAdapterInfo = pAdapterInfo->Next;
		}
	}
	return !ip.empty() && !mac.empty();
}

// 获取同网段所有 IP（假设 /24 子网）
vector<string> arp::get_ips_in_subnet(const string& ip) {
	vector<string> ips;
	size_t last_dot = ip.rfind('.');
	string prefix = ip.substr(0, last_dot + 1);
	for (int i = 1; i < 255; ++i) {
		ips.push_back(prefix + to_string(i));
	}
	return ips;
}

// 发送 ARP 请求并收集结果（伪实现）
void arp::arp_request(const string& target_ip, CListCtrl* pListCtrl) {
	uint8_t tagetip[4];
	uint8_t srcip[4];
	uint8_t srcmac[6];
	string_ip_to_uint8(target_ip, tagetip);
	string ip, mac;
	this->get_device_ip_mac(this->device_name, ip, mac);
	string_ip_to_uint8(ip, srcip);
	macToUint8(mac, srcmac);
	// 发送 ARP 请求
	sendArp(srcip, srcmac, tagetip);
	//接受 ARP 响应
	mac = recvArp(srcip, tagetip);
	lock_guard<mutex> lock(results_mutex);

	if (mac != "00:00:00:00:00:00") {
		scan_results[target_ip] = mac;
		//更新列表
		CString str_ip(target_ip.c_str());
		CString str_mac(scan_results[target_ip].c_str());
		int nIndex = pListCtrl->InsertItem(pListCtrl->GetItemCount(), str_ip);
		pListCtrl->SetItemText(nIndex, 1, str_mac);
		pListCtrl->EnsureVisible(nIndex, FALSE);
		pListCtrl->UpdateWindow();
	}

	Sleep(1000);
}

void arp::scan_ip(const string& ip, const string& mac, int threadCount, CListCtrl* pListCtrl, BOOL* threadflag) {
	scan_results.clear();
	ips_Count = 0;

	vector<string> ips = get_ips_in_subnet(ip);
	size_t total = ips.size();
	//分线程执行相同的数量
	size_t batch = total / threadCount;
	vector<thread> threads;

	////接受 ARP 响应的线程
	//thread RecvArpThread([this]() {
	//	string ip, mac;
	//	uint8_t ip_uint8[4];
	//	this->get_device_ip_mac(device_name,ip,mac);
	//	this->string_ip_to_uint8(ip, ip_uint8);
	//	this->recvArp(ip_uint8);
	//});
	//RecvArpThread.detach(); // 分离线程，避免阻塞

	// 使用 lambda 函数创建工作线程
	auto worker = [this, &ips, pListCtrl, threadflag](size_t start, size_t end) {
		for (size_t i = start; i < end; ++i) {
			arp_request(ips[i], pListCtrl);
			if (*threadflag == FALSE)
			{
				MessageBox(NULL,L"扫描已停止", L"提示", MB_OK | MB_ICONINFORMATION);
				break;
			}
			this->ips_Count++;
		}
		};

	for (int t = 0; t < threadCount; ++t) {
		size_t start = t * batch;
		size_t end = (t == threadCount - 1) ? total : start + batch;
		threads.emplace_back(worker, start, end);
	}

	for (auto& th : threads) th.join();

}

void arp::ShowError(string msg, const char* tishi)
{
	MessageBoxA(NULL, msg.c_str(), tishi, MB_ICONERROR | MB_OK);
}