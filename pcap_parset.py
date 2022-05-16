from scapy.all import *
import os
from tqdm import tqdm


def make_pcap_payload(pcap_file, session=True):
    folder_name = pcap_file + "_Payload(Session)"
    if os.path.getsize(pcap_file) == 0:  # PCAP이 비어있을 경우 작업 X
        print(pcap_file, "No data")
        return None
    if not os.path.exists(folder_name):  # Payload만 추출된 txt파일 저장 폴더 생성
        os.mkdir(folder_name)
    if session: # TCP 세션을 생성하는 경우 -> 분석을 위해 PCAP 이름/SESSION/5Tuple 구조로 저장
        sessions = rdpcap(pcap_file).sessions() # PCAP에서 TCP 세션을 모두 생성하여 리스트로 저장 key: 5tuple, value: session packets
        session_set = set() # sessions에는 세션들의 단방향 정보만 있기 때문에 대칭되는 단방향 session 두개를 합쳐서 저장하고 사용된 Session은 추가로 작업하지 않기 위해 set에 저장
        for idx, session in enumerate(sessions):
            if session not in session_set: # 중복으로 작업하지 않기 위해 작업된 session은 넘어감
                tmp = session.split(' ')
                if len(tmp) < 4: # split 후에 4개 이하일 경우에는 ethernet session으로만 맺어져 있어 payload가 없기 때문에 버림
                    continue
                reverse_session = ' '.join([tmp[0], tmp[3], tmp[2], tmp[1]]) # 읽은 세션에 대해 대칭되는 세션 정보를 가져옴
                second_folder_name = '_'.join([str(idx + 1), tmp[0], tmp[1], tmp[3]]).replace(':', '_')
                os.mkdir(rf"{folder_name}{os.sep}{second_folder_name}") # SESSION 폴더 생성
                if reverse_session in sessions: # 대칭되는 세션을 합친 뒤 안에 패킷을 시간순서로 정렬
                    packet_list = sorted(sessions[session] + sessions[reverse_session], reverse=False, key=lambda x:x.time)
                else: # 대칭되는 세션이 없을 경우 현 세션만 저장
                    packet_list = sessions[session]
                for i, packet in enumerate(packet_list): # 세션 내에서 패킷을 순서대로 읽어 5Tuple정보를 얻어내고 해당 파일 이름을 만듬
                    protocol = tmp[0]
                    if packet.haslayer('IP') and not packet.haslayer('TCP') and not packet.haslayer('UDP'):
                        protocol = 'IP'
                        file_name = f"{i+1}_{packet['IP'].src}_{packet['IP'].dst}"
                    else:
                        file_name = f"{i+1}_{packet['IP'].src}_{packet[tmp[0]].sport}_{packet['IP'].dst}_{packet[tmp[0]].dport}"
                    with open(rf"{folder_name}{os.sep}{second_folder_name}{os.sep}{file_name}.txt", 'w', encoding='utf-8') as f: # 만들어진 파일 이름으로 해당 패킷에서 payload만 추출하여 txt파일로 저장
                        f.write(bytes(packet[protocol].payload).hex() + '\n') # 저장은 hex string으로 저장함
                session_set.add(session) # 작업된 session을 추가작업 하지 않기 위해 check
                session_set.add(reverse_session)
    else:
        pkts = rdpcap(pcap_file) # pcap 전체를 읽어 시간 순으로 패킷이 저장됨
        for i, pkt in enumerate(pkts): # 각 패킷에서 5tuple을 추출하여 파일 이름을 만들고 payload를 저장함
            if pkt.haslayer('IP'):
                sip = pkt['IP'].src
                dip = pkt['IP'].dst
                if pkt.haslayer('TCP'):
                    protocol = 'TCP'
                elif pkt.haslayer('UDP'):
                    protocol = 'UDP'
                else:
                    with open(rf"{folder_name}{os.sep}{i + 1}_{sip}_{dip}.txt", 'w', encoding='utf-8') as f:
                        f.write(bytes(pkt['IP'].payload).hex() + '\n')
                    continue
                with open(rf"{folder_name}{os.sep}{i + 1}_{sip}_{pkt[protocol].sport}_{dip}_{pkt[protocol].dport}.txt",
                          'w', encoding='utf-8') as f:
                    f.write(bytes(pkt[protocol].payload).hex() + '\n')
            else:
                pass


if __name__ == '__main__':
    pcap_path = r"test"
    for pcap_file in tqdm(os.listdir(pcaps_path)):
        pcap_path = os.path.join(pcaps_path, pcap_file)
        make_pcap_payload(pcap_path, session=True) # PCAP 위치 넣어주기
