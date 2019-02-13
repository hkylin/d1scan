from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from asset.models import DomainList
import whois
import nmap
from urllib import request as r

headers = {
    'User-Agent': r'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  r'Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3'
}


def who_is(request, action=None):

    if request.method == 'POST':

        target = request.POST.get('arg')
        res = whois.whois(target)
        result = request.GET.get('result')
        result = res
        return render(request, 'info/who_is.html', {'result': result})

    else:
        return render(request, 'info/who_is.html')


def subdomain_scan(request):
    if request.method == 'POST':
        domain_list = DomainList.objects.all()
        data = {
            'domain_list': domain_list,
        }
        target = request.POST.get('id_tgt_select[]')

        return render(request, 'info/subdomain_scan.html', data)

    else:
        domain_list = DomainList.objects.all()
        data = {
            'domain_list': domain_list,
        }
        return render(request, 'info/subdomain_scan.html', data)


def port_scan(request):

    if request.method == 'POST':

        ip_list = DomainList.objects.all()
        techniques_list = ['-sS', '-sT', '-sA', '-sU']
        service_list = ['-sV', '--version-intensity', '--version-light', '--version-all']
        result = request.GET.get('result')
        target = request.POST.get('id_tgt_select[]')
        techniques = request.POST.get('techniques_tgt_select[]')
        service = request.POST.get('service_tgt_select[]')
        port = request.POST.get('arg')

        defaultcmd = '-Pn'
        portcmd = '-p' + request.POST.get('arg')
        cmd = service + ' ' + defaultcmd + ' ' + portcmd

        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=cmd)
        commandline = nm.command_line()
        info = nm[target]

        data = {
            'ip_list': ip_list,
            'techniques_list': techniques_list,
            'service_list': service_list,
            'arg': port,
            'cmd': commandline,
            'result': info,
        }

        return render(request, 'info/port_scan.html', data)

    elif request.method == 'GET':
        ip_list = DomainList.objects.all()
        techniques_list = ['-sS | TCP SYN Scan', '-sT | Connect Scan', '-sA | ACK Scan', '-sU | UDP Scan']
        service_list = ['-sV', '--version-intensity', '--version-light', '--version-all']
        data = {
            'ip_list': ip_list,
            'techniques_list': techniques_list,
            'service_list': service_list,
        }

        return render(request, 'info/port_scan.html', data)


def identify_web(request):
    return HttpResponse('identify web')


def ip_blacklist(request):

    feed_list = ['Cisco Talos', 'Abuse.ch勒索软件']
    if request.method == 'POST':

        target = request.POST.get('feed_tgt_select[]')

        if target == 'Cisco Talos':

            target_ulr = 'https://talosintelligence.com/documents/ip-blacklist'
            html = r.Request(target_ulr, headers=headers)
            res = r.urlopen(html).read()
            res = res.decode('utf-8')

            data = {
                'feed_list': feed_list,
                'result': res
            }

            return render(request, 'info/ip_blacklist.html', data)

        elif target == 'Abuse.ch勒索软件':

            target_ulr = 'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt'
            html = r.Request(target_ulr, headers=headers)
            res = r.urlopen(html).read()
            res = res.decode('utf-8')
            data = {
                'feed_list': feed_list,
                'result': res
            }

            return render(request, 'info/ip_blacklist.html', data)
    else:

        data = {
            'feed_list': feed_list,
        }

        return render(request, 'info/ip_blacklist.html', data)
