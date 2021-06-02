#!/usr/bin/env python
from OTXv2 import OTXv2
from pymisp import PyMISP, MISPEvent, PyMISPError
from datetime import date
from dateutil.parser import *
import configparser
import argparse
import sys
import os


def config_parser(section, key):
    config = configparser.ConfigParser()
    try:
        config.read(os.path.join(os.path.dirname(__file__)+"/config/config.ini"))
        result = config.get(section, key)
        return result
    except config.NoOptionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")
    except config.NoSectionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")


def load_file(filename):
    with open(os.path.dirname(__file__)+"/config/"+filename, "r") as ins:
        array = []
        for line in ins:
            array.append(line.strip())
        ins.close()
    return array


def misp_connection(url, misp_key, proxy_usage):
    try:
        if proxy_usage:
            proxies = {}
            proxies ["http"] = config_parser("misp","http")
            proxies ["https"] = config_parser("misp","https")
            misp = PyMISP(url, misp_key, False, 'json', proxies=proxies)
        else:
            misp = PyMISP(url, misp_key, False, 'json',None)
    except PyMISPError:
        print("\t [!] Error connecting to MISP instance. Check if your MISP instance it's up!")
        return None

    return misp


def create_event(misp):
    event = MISPEvent()
    event.distribution = 0
    event.threat_level_id = 1
    event.analysis = 0
    return event


def send2misp(tweet, proxy_usage):
    url = config_parser("misp", "url")
    api_key = config_parser("misp", "api_key")
    misp = misp_connection(url, api_key, proxy_usage)
    event = create_event(misp)
    event.add_tag("OTX")
    event.info = "[OTX] New threat discovered on OTX-AT&T"
    event.add_attribute('twitter-id', tweet.user.screen_name)
    event.add_attribute('other', tweet.text)
    event.add_attribute('other', tweet.created_at.strftime("%Y-%m-%dT%H:%M:%S"))
    if 'hashtags' in tweet.entities:
        for h in tweet.entities['hashtags']:
            event.add_attribute('other', h['text'])
    if 'urls' in tweet.entities:
        for h in tweet.entities['urls']:
            event.add_attribute('link', h['url'])
    event = misp.add_event(event, pythonify=True)
    print("\t [*] Event with ID " + str(event.id) + " has been successfully stored.")


def check_att(key, att):
    if type(att) == list and len(att) == 0:
        print("\t\t [-] " + key + ": " + "Unknown")
    elif (att is not None) and (not att) and (att is not " ") and (att is not ''):
        print("\t\t [-] "+key+": " + str(att))
    else:
        print("\t\t [-] "+key+": " + "Unknown")


def show_tags(tags):
    tag_chain = ""
    if len(tags)>0:
        for tag in tags:
            tag_chain = tag_chain + "#"+tag.replace(" " , "")+" "
        print("\t\t [-] Tags: " + tag_chain.strip())


def show_ioc(ioc):
    print("\t\t\t [-] New IoC with ID: " + str(ioc['id']))
    print("\t\t\t\t [-] IoC: " + str(ioc['indicator']))
    print("\t\t\t\t [-] type: " + ioc['type'])
    if (ioc['content'] is not None) and (ioc['content'] is not " ") and (ioc['content'] is not ''):
        print("\t\t\t\t [-] Content: " + ioc['content'].replace("\n", "\n\t\t\t\t\t"))
    print("\t\t\t\t [-] created: " + str(ioc['created']))
    if (ioc['title'] is not '') and (ioc['title'] is not None):
        print("\t\t\t\t [-] title: " + str(ioc['title']))
    if ioc['description'] is not '':
        print("\t\t\t\t [-] description: " + str(ioc['description']))
    if ioc['role'] is not None and ioc['role'] is not '':
        print("\t\t\t\t [-] role: " + str(ioc['role']))


def show_references(references):
    if len(references) > 0:
        print("\t\t [-] References: ")
        for r in references:
            print("\t\t\t [+] link: "+r)


def show_pulse(pulse):
    print("\t[+] New OTX Pulse by "+ pulse['author_name'] + ' created: '+pulse['created'])
    if pulse['modified'] is not '':
        print("\t\t [-] This pulse was edited: "+pulse['modified'])
    print("\t\t [-] Title: " + pulse['name'])
    print("\t\t [-] ID: " + pulse['id'])
    print("\t\t [-] TLP: " + pulse['tlp'])
    check_att("Description", pulse['description'])
    check_att("Malware families", pulse['malware_families'])
    check_att("Targeted countries", pulse['targeted_countries'])
    check_att("Adversary", pulse['adversary'])
    check_att("ATT&CK Techniques", pulse['attack_ids'])
    show_tags(pulse["tags"])
    show_references(pulse['references'])
    print("\t\t [-] IoCs associated with this pulse:")
    for ioc in pulse['indicators']:
        show_ioc(ioc)


def filter_pulse_by_attck_technique(pulse, techniques_list):
    contains_technique = False
    for k in techniques_list:
        if k in pulse['attack_ids']:
            return True

    return contains_technique


def filter_pulse_by_keyword(pulse, keywords_list):
    contains_alerts = False
    for k in keywords_list:
        if (k in pulse['name']) or k in (pulse['description']) or (k.replace(" ", "") in pulse['tags']):
            return True

    return contains_alerts


def search_on_otx(api, alerts, techniques, max_days):
    pulse_list = []
    keywords_list = load_file("keywords.txt")
    techniques_list = load_file("attack_ids.txt")
    today = date.today()
    date_today = today.strftime("%Y-%m-%d")
    now = parse(date_today)
    pulses = api.getall()
    for pulse in pulses:
        threat = parse(pulse['created'])
        days = now - threat
        if days.days <= int(max_days):
            if alerts:
                if techniques:
                    contains_alert = filter_pulse_by_keyword(pulse, keywords_list)
                    contains_technique = filter_pulse_by_attck_technique(pulse, techniques_list)
                    if contains_technique or contains_alert:
                        show_pulse(pulse)
                        pulse_list.append(pulse)
                else:
                    contains_alert = filter_pulse_by_keyword(pulse, keywords_list)
                    if contains_alert:
                        show_pulse(pulse)
                        pulse_list.append(pulse)
            elif techniques:
                contains_technique = filter_pulse_by_attck_technique(pulse, techniques_list)
                if contains_technique:
                    show_pulse(pulse)
                    pulse_list.append(pulse)

            else:
                show_pulse(pulse)
                pulse_list.append(pulse)

    print("[*] Number of OTX Pulses gathered: " + str(len(pulse_list)))

    return pulse_list


def start_listen_otx():
    api_key = config_parser("otx", "api_key")
    otx_server = config_parser("otx", "otx_server")
    api = OTXv2(api_key, server=otx_server)
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--alerts", help=" Filter OTX pulses gathered in case of a match with any "
                                               "keywords of your list.",
                                               action="store_true")
    parser.add_argument("-d", "--days", help=" Filter OTX pulses by days (e.g. Last 7 days: -d 7 )")
    parser.add_argument("-m", "--misp", help="Send IoCs from Twitter to MISP", action="store_true")
    parser.add_argument("-p", "--proxy", help="Set a proxy for sending the alert to your MISP instance..",
                        action="store_true")
    parser.add_argument("-t", "--techniques", help=" Filter OTX pulses gathered in case of a match with any "
                                               "ATT&CK techniques of your list.",
                                               action="store_true")
    args = parser.parse_args()
    proxy_usage = False
    print("[*] Searching for Pulses on OTX:")
    if args.days:
        max_days = args.days
    else:
        max_days = 7

    if args.alerts:
        print("[*] Checking if the pulses gathered contain any keyword from your list.")
        if args.techniques:
            pulses = search_on_otx(api, True, True, max_days)
        else:
            pulses = search_on_otx(api, True, False, max_days)
        if args.misp:
            if args.proxy:
                proxy_usage = True
            print("[*] Sending alerts to MISP")
            '''for t in pulses:
                send2misp(t, proxy_usage)'''
        sys.exit(0)
    elif args.techniques:
        print("[*] Checking if the pulses gathered gathered contain any ATT&CK Technique from your list.")
        pulses = search_on_otx(api, False, True, max_days)
        if args.misp:
            if args.proxy:
                proxy_usage = True
            print("[*] Sending alerts to MISP")
            '''for t in pulses:
                send2misp(t, proxy_usage)'''
        sys.exit(0)

    else:
        search_on_otx(api, False, False, max_days)


if __name__ == '__main__':
    start_listen_otx()