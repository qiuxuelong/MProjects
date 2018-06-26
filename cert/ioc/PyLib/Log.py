#!/usr/bin/python
import IcmpAnalyser
import DnsAnalyser
import SnmpAnalyser

import PortProtocolDetector


def FlushLog():

    IcmpAnalyser.FlushLog()

    DnsAnalyser.FlushLog()

    SnmpAnalyser.flushLog()

    PortProtocolDetector.FlushLog()

