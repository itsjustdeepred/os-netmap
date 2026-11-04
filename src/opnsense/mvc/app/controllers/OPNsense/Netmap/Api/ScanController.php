<?php

/*
 * Copyright (C) 2026 os-netmap contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Netmap\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Port scan of one device with nmap. The backend only scans addresses on
 * networks attached to the firewall (not the uplink, not VPNs).
 */
class ScanController extends ApiControllerBase
{
    private function valid($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    private function run($action, $params)
    {
        if (method_exists($this, 'sessionClose')) {
            $this->sessionClose();
        }
        $response = trim((new Backend())->configdpRun('netmap scan ' . $action, $params));
        return json_decode($response, true) ?? ['status' => 'error', 'message' => $response];
    }

    public function startAction($ip = '', $profile = 'quick')
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        if (!$this->valid($ip) || !in_array($profile, ['quick', 'full'], true)) {
            return ['status' => 'error', 'message' => 'invalid request'];
        }
        return $this->run('start', [$ip, $profile]);
    }

    public function statusAction($ip = '')
    {
        if (!$this->valid($ip)) {
            return ['status' => 'error', 'message' => 'invalid address'];
        }
        return $this->run('status', [$ip]);
    }
}
