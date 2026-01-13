import threading
import time
import statistics
import csv
import re
import matplotlib.pyplot as plt
import numpy as np
import argparse
from mininet.net import Mininet
from mininet.node import OVSController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

cmd_lock = threading.Lock()

def start_tshark(host, interface, output_file):
    with cmd_lock:
        host.cmd(f'tshark -i {interface} -t e -Y "tcp.analysis.retransmission" > {output_file} 2>&1 &')

def stop_tshark(host):
    with cmd_lock:
        host.cmd("killall tshark")

def count_retransmissions(file_path):
    count = 0
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    count += 1
    except Exception as e:
        info(f"Ошибка при чтении файла tshark: {e}\n")
    return count

def parse_tshark_timestamps(file_path):
    times = []
    start_time = None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                tokens = line.strip().split()
                if len(tokens) >= 2:
                    try:
                        t = float(tokens[1])
                        if start_time is None:
                            start_time = t
                        times.append(t - start_time)
                    except ValueError:
                        continue
    except Exception as e:
        info(f"Ошибка при парсинге tshark: {e}\n")
    return times

def plot_retransmissions_over_time_line(times, output="retransmissions_over_time.png", bin_size=1):
    if not times:
        info("Нет данных для построения графика повторных передач.\n")
        return
    max_time = max(times)
    bins = np.arange(0, max_time + bin_size, bin_size)
    counts, edges = np.histogram(times, bins=bins)
    midpoints = (edges[:-1] + edges[1:]) / 2
    plt.figure()
    plt.plot(midpoints, counts, marker='o', linestyle='-')
    plt.title("Количество повторных передач во времени")
    plt.xlabel("Время (с)")
    plt.ylabel("Количество повторных передач")
    plt.grid(True)
    plt.savefig(output)
    info(f"Линейный график повторных передач сохранен в {output}\n")

def ping_measurement(h1, h2, duration, interval, results):
    end_time = time.time() + duration
    while time.time() < end_time:
        with cmd_lock:
            output = h1.cmd(f'ping -c 1 {h2.IP()}')
        latency = None
        loss = None
        for line in output.splitlines():
            if 'time=' in line:
                try:
                    match = re.search(r'time=([\d\.]+)', line)
                    if match:
                        latency = float(match.group(1))
                except Exception:
                    pass
        match_loss = re.search(r'(\d+)% packet loss', output)
        if match_loss:
            loss = float(match_loss.group(1))
        else:
            loss = 100.0
        results['ping'].append({'latency': latency, 'loss': loss})
        time.sleep(interval)

def iperf_measurement(h1, h2, duration, interval, results):
    with cmd_lock:
        h2.cmd('iperf -s &')
    time.sleep(1)
    end_time = time.time() + duration
    while time.time() < end_time:
        with cmd_lock:
            output = h1.cmd(f'iperf -c {h2.IP()} -t 1')
        throughput = None
        for line in output.splitlines():
            if "Mbits/sec" in line:
                tokens = line.split()
                try:
                    throughput = float(tokens[-2])
                except Exception:
                    throughput = None
        results['iperf'].append(throughput)
        time.sleep(interval)
    with cmd_lock:
        h2.cmd("killall iperf")

def main_measurement(h1, h2, duration=60, interval=1):
    results = {'ping': [], 'iperf': []}
    ping_thread = threading.Thread(target=ping_measurement, args=(h1, h2, duration, interval, results))
    iperf_thread = threading.Thread(target=iperf_measurement, args=(h1, h2, duration, interval, results))
    ping_thread.start()
    iperf_thread.start()
    ping_thread.join()
    iperf_thread.join()
    return results

def compute_stats(data):
    if not data:
        return None
    data_sorted = sorted(data)
    avg = statistics.mean(data_sorted)
    med = statistics.median(data_sorted)
    index_95 = int(0.95 * len(data_sorted)) - 1
    p95 = data_sorted[index_95] if index_95 >= 0 else None
    mn = data_sorted[0]
    mx = data_sorted[-1]
    std = statistics.stdev(data_sorted) if len(data_sorted) > 1 else 0
    return {
        'average': avg,
        'median': med,
        '95th_percentile': p95,
        'min': mn,
        'max': mx,
        'std_dev': std
    }

def analyze_results(results):
    latencies = [r['latency'] for r in results['ping'] if r['latency'] is not None]
    losses = [r['loss'] for r in results['ping'] if r['loss'] is not None]
    throughputs = [t for t in results['iperf'] if t is not None]
    stats = {
        'Latency (ms)': compute_stats(latencies),
        'Packet Loss (%)': compute_stats(losses),
        'Throughput (Mbits/sec)': compute_stats(throughputs)
    }
    return stats

def save_results_csv(stats, filename="qos_results.csv"):
    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = [
            'Параметр QoS',
            'Среднее значение',
            'Медиана',
            '95-й процентиль',
            'Минимальное значение',
            'Максимальное значение',
            'Стандартное отклонение'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for param, data in stats.items():
            if data is not None:
                writer.writerow({
                    'Параметр QoS': param,
                    'Среднее значение': data['average'],
                    'Медиана': data['median'],
                    '95-й процентиль': data['95th_percentile'],
                    'Минимальное значение': data['min'],
                    'Максимальное значение': data['max'],
                    'Стандартное отклонение': data['std_dev']
                })

def plot_histograms(results):
    latencies = [r['latency'] for r in results['ping'] if r['latency'] is not None]
    if latencies:
        plt.figure()
        plt.hist(latencies, bins=10)
        plt.title("Гистограмма задержки")
        plt.xlabel("Задержка (ms)")
        plt.ylabel("Частота")
        plt.savefig("latency_histogram.png")
    losses = [r['loss'] for r in results['ping'] if r['loss'] is not None]
    if losses:
        plt.figure()
        plt.hist(losses, bins=10)
        plt.title("Гистограмма потерь пакетов")
        plt.xlabel("Потери пакетов (%)")
        plt.ylabel("Частота")
        plt.savefig("packet_loss_histogram.png")
    throughputs = [t for t in results['iperf'] if t is not None]
    if throughputs:
        plt.figure()
        plt.hist(throughputs, bins=10)
        plt.title("Гистограмма пропускной способности")
        plt.xlabel("Пропускная способность (Mbits/sec)")
        plt.ylabel("Частота")
        plt.savefig("throughput_histogram.png")

def run_experiment(delay_ms, loss_pct, duration=15):
    net = Mininet(controller=OVSController, link=TCLink, switch=OVSKernelSwitch)
    net.addController('c0')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    s1 = net.addSwitch('s1')
    delay_str = f"{delay_ms}ms"
    net.addLink(h1, s1, cls=TCLink, delay=delay_str, loss=loss_pct, bw=10)
    net.addLink(h2, s1, cls=TCLink, delay=delay_str, loss=loss_pct, bw=10)
    net.start()
    results = {'iperf': []}
    h2.cmd('iperf -s &')
    time.sleep(1)
    end_time = time.time() + duration
    while time.time() < end_time:
        with cmd_lock:
            output = h1.cmd(f'iperf -c {h2.IP()} -t 1')
        throughput = None
        for line in output.splitlines():
            if "Mbits/sec" in line:
                tokens = line.split()
                try:
                    throughput = float(tokens[-2])
                except Exception:
                    throughput = None
        if throughput:
            results['iperf'].append(throughput)
        time.sleep(1)
    h2.cmd("killall iperf")
    net.stop()
    if results['iperf']:
        avg_throughput = statistics.mean(results['iperf'])
    else:
        avg_throughput = 0
    return avg_throughput

def experiment_grid():
    delays = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    losses = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 1.8, 2.0]
    throughput_matrix = np.zeros((len(delays), len(losses)))
    for i, d in enumerate(delays):
        for j, l in enumerate(losses):
            info(f"*** Эксперимент: delay={d}ms, loss={l}%\n")
            avg_thr = run_experiment(d, l)
            throughput_matrix[i, j] = avg_thr
            info(f"    Средняя пропускная способность: {avg_thr} Mbits/sec\n")
    plt.figure(figsize=(8,6))
    plt.imshow(throughput_matrix, origin='lower', aspect='auto', cmap='hot')
    plt.colorbar(label="Throughput (Mbits/sec)")
    plt.title("Зависимость пропускной способности от задержки и потерь")
    plt.xlabel("Потери (%)")
    plt.ylabel("Задержка (ms)")
    plt.xticks(ticks=range(len(losses)), labels=losses)
    plt.yticks(ticks=range(len(delays)), labels=delays)
    plt.savefig("throughput_heatmap.png")
    info("Тепловая карта сохранена в throughput_heatmap.png\n")

def run_experiment_mode(mode):
    if mode == "single":
        create_topology_and_measure()
    elif mode == "grid":
        experiment_grid()
    else:
        info("Неверный режим работы\n")

def create_topology_and_measure():
    net = Mininet(controller=OVSController, link=TCLink, switch=OVSKernelSwitch)
    info("*** Добавление контроллера\n")
    net.addController('c0')
    info("*** Добавление хостов\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    info("*** Добавление коммутатора\n")
    s1 = net.addSwitch('s1')
    info("*** Соединение хостов с коммутатором с параметрами QoS\n")
    net.addLink(h1, s1, cls=TCLink, delay='10ms', loss=0.5, bw=10)
    net.addLink(h2, s1, cls=TCLink, delay='10ms', loss=0.5, bw=10)
    info("*** Запуск сети\n")
    net.start()
    tcpdump_file = "tshark_output.txt"
    info("*** Запуск tshark для захвата пакетов\n")
    start_tshark(h2, "h2-eth0", tcpdump_file)
    info("*** Запуск измерений QoS (1 минута)\n")
    results = main_measurement(h1, h2, duration=60, interval=1)
    info("*** Остановка tshark\n")
    stop_tshark(h2)
    time.sleep(1)
    retransmissions = count_retransmissions(tcpdump_file)
    info(f"Количество retransmission-пакетов: {retransmissions}\n")
    times = parse_tshark_timestamps(tcpdump_file)
    plot_retransmissions_over_time_line(times)
    info("*** Анализ результатов измерений\n")
    stats = analyze_results(results)
    for param, data in stats.items():
        info(f"{param}: {data}\n")
    save_results_csv(stats)
    info("*** Результаты сохранены в файле qos_results.csv\n")
    plot_histograms(results)
    info("*** Гистограммы сохранены в PNG-файлах\n")
    info("*** Тестирование соединения (pingAll)\n")
    net.pingAll()
    info("*** Запуск командной строки Mininet (CLI)\n")
    CLI(net)
    info("*** Остановка сети\n")
    net.stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mininet QoS Measurement and Experiment Grid")
    parser.add_argument(
        '--mode',
        type=str,
        default="single",
        choices=["single", "grid"],
        help="Выберите режим работы: 'single' - одиночный эксперимент (измерения в течение 1 минуты), 'grid' - перебор параметров сети (heatmap)"
    )
    args = parser.parse_args()
    setLogLevel('info')
    run_experiment_mode(args.mode)