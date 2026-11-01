#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Optional export of actual loadlab JSON measurements (requires matplotlib)."""
import argparse, datetime, json, pathlib
from zoneinfo import ZoneInfo
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('evidence',type=pathlib.Path)
    args=parser.parse_args();root=args.evidence
    result=json.loads((root/'result.json').read_text());samples=[json.loads(x) for x in (root/'samples.jsonl').read_text().splitlines()]
    start=samples[0]['at'];x=[s['at']-start for s in samples]
    fig,axes=plt.subplots(2,2,figsize=(14,9),layout='constrained')
    date=datetime.datetime.fromisoformat(result['started_at']).astimezone(ZoneInfo('Europe/Moscow')).strftime('%d.%m.%Y')
    fig.suptitle('CERBER · нагрузка и восстановление · '+date,fontsize=18,fontweight='bold')
    steady=[p for p in result['phases'] if p['phase'].startswith('steady_')]
    a=axes[0,0];values=[p['latency_ms']['correlation_observed_p95']/1000 for p in steady]
    bars=a.bar([str(p['target_pps']) for p in steady],values,color=['#8398ac','#8398ac','#b56743'])
    a.bar_label(bars,labels=[f'{v:.2f} с' for v in values],padding=4)
    a.set(title='Задержка до наблюдения корреляции, p95',xlabel='Заданная нагрузка, пакетов/с',ylabel='Секунды',ylim=(0,max(values)*1.2))
    a=axes[0,1]
    for key,label,color in [('source_backlog_records','Непрочитанный EVE','#335f82'),('queue_records','Durable spool','#b56743'),('pending_normalization','Нормализация','#777777')]:
        a.plot(x,[s.get(key,0) for s in samples],label=label,color=color,lw=1.5)
    a.set(title='Накопление записей по участкам цепочки',xlabel='Время от начала наблюдения, с',ylabel='Записи');a.legend(fontsize=9)
    for name,label,color in [('suricata','Suricata','#335f82'),('sensor','Сенсор','#6f8872'),('siem','SIEM','#b56743')]:
        pairs=[(s['at']-start,s['processes'][name]) for s in samples if name in s['processes']]
        axes[1,0].plot([t for t,v in pairs],[v['cpu_percent'] for t,v in pairs],label=label,color=color,lw=1)
        axes[1,1].plot([t for t,v in pairs],[v['rss_bytes']/1048576 for t,v in pairs],label=label,color=color,lw=1.5)
    axes[1,0].set(title='CPU процессов, включая запуск и восстановление',xlabel='Время от начала наблюдения, с',ylabel='% одного логического ядра');axes[1,0].legend(fontsize=9)
    axes[1,1].set(title='Резидентная память процессов',xlabel='Время от начала наблюдения, с',ylabel='RSS, МиБ (логарифмическая шкала)',yscale='log');axes[1,1].legend(fontsize=9)
    for a in axes.flat:
        a.spines[['top','right']].set_visible(False);a.grid(axis='y',alpha=.18);a.set_axisbelow(True)
    interval=max(b['at']-a['at'] for a,b in zip(samples,samples[1:]))
    fig.supxlabel(f'Источник: samples.jsonl + result.json · Linux {result["architecture"]}, Docker 4 CPU / 4 ГиБ · UDP-серии, не физический SPAN\n{result["suricata_version"]} · интервал наблюдения ≤ {interval:.3f} с · SMTP/active response отсутствуют',fontsize=10)
    fig.savefig(root/'loadlab.png',dpi=160);fig.savefig(root/'loadlab.pdf')
    print(root/'loadlab.png')

if __name__=='__main__':main()
