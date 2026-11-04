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
use OPNsense\Netmap\Netmap;

/**
 * Bridge to the AdGuard Home API. The firewall talks to AdGuard Home so its
 * password never reaches the browser.
 */
class AdguardController extends ApiControllerBase
{
    private function request($method, $path, $body = null)
    {
        $ag = (new Netmap())->adguard;
        if ((string)$ag->enabled !== '1' || (string)$ag->url === '') {
            return [0, null, 'AdGuard Home is not set up in Network Map > Settings'];
        }
        $verify = (string)$ag->verify_tls === '1';
        $ch = curl_init(rtrim((string)$ag->url, '/') . $path);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_USERPWD => (string)$ag->username . ':' . (string)$ag->password,
            CURLOPT_SSL_VERIFYPEER => $verify,
            CURLOPT_SSL_VERIFYHOST => $verify ? 2 : 0,
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        }
        $out = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($out === false) {
            return [0, null, 'AdGuard Home does not answer: ' . $err];
        }
        if ($code === 401 || $code === 403) {
            return [$code, null, 'AdGuard Home refused the user name or password'];
        }
        if ($code >= 400) {
            return [$code, null, 'AdGuard Home answered HTTP ' . $code];
        }
        $data = json_decode($out, true);
        return [$code, $data === null && trim($out) !== '' ? $out : $data, null];
    }

    private function validIp($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public function testAction()
    {
        list($code, $data, $err) = $this->request('GET', '/control/status');
        if ($err) {
            return ['status' => 'error', 'message' => $err];
        }
        return ['status' => 'ok', 'version' => $data['version'] ?? '', 'protection' => !empty($data['protection_enabled'])];
    }

    /**
     * Domains asked by one client (by address), from the AdGuard Home query log.
     */
    public function queriesAction($ip = '')
    {
        if (!$this->validIp($ip)) {
            return ['status' => 'error', 'message' => 'invalid address'];
        }
        list($code, $data, $err) = $this->request('GET', '/control/querylog?limit=1000&search=' . rawurlencode($ip));
        if ($err) {
            return ['status' => 'error', 'message' => $err];
        }
        $domains = [];
        $total = 0;
        $blocked = 0;
        $oldest = null;
        foreach (($data['data'] ?? []) as $q) {
            if (($q['client'] ?? '') !== $ip) {
                continue;  // the search also matches answers and domain names
            }
            $name = rtrim((string)($q['question']['name'] ?? ''), '.');
            if ($name === '') {
                continue;
            }
            $isBlocked = strpos((string)($q['reason'] ?? ''), 'Filtered') === 0;
            $total++;
            $blocked += $isBlocked ? 1 : 0;
            $oldest = $q['time'] ?? $oldest;
            if (!isset($domains[$name])) {
                $domains[$name] = ['name' => $name, 'count' => 0, 'blocked' => 0, 'last' => $q['time'] ?? '', 'rule' => ''];
            }
            $domains[$name]['count']++;
            if ($isBlocked) {
                $domains[$name]['blocked']++;
                $domains[$name]['rule'] = (string)($q['rules'][0]['text'] ?? $q['rule'] ?? '');
            }
        }
        usort($domains, function ($a, $b) {
            return ($b['blocked'] > 0) <=> ($a['blocked'] > 0) ?: $b['count'] <=> $a['count'];
        });
        list(, $access) = $this->request('GET', '/control/access/list');
        $disallowed = is_array($access) ? ($access['disallowed_clients'] ?? []) : [];
        return ['status' => 'ok', 'total' => $total, 'blocked' => $blocked, 'since' => $oldest,
            'domains' => array_slice($domains, 0, 40), 'dns_blocked' => in_array($ip, $disallowed ?: [], true)];
    }

    /**
     * POST: add (block=1) or remove (block=0) the address from the AdGuard Home disallowed clients.
     */
    public function blockAction($ip = '', $block = '1')
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        if (!$this->validIp($ip)) {
            return ['status' => 'error', 'message' => 'invalid address'];
        }
        list(, $access, $err) = $this->request('GET', '/control/access/list');
        if ($err || !is_array($access)) {
            return ['status' => 'error', 'message' => $err ?: 'unexpected answer from AdGuard Home'];
        }
        $list = array_values(array_filter($access['disallowed_clients'] ?? [], function ($c) use ($ip) {
            return $c !== $ip;
        }));
        if ($block === '1') {
            $list[] = $ip;
        }
        $access['disallowed_clients'] = $list;
        foreach (['allowed_clients', 'blocked_hosts'] as $key) {
            $access[$key] = $access[$key] ?? [];
        }
        list(, , $err) = $this->request('POST', '/control/access/set', [
            'allowed_clients' => $access['allowed_clients'],
            'disallowed_clients' => $access['disallowed_clients'],
            'blocked_hosts' => $access['blocked_hosts'],
        ]);
        return $err ? ['status' => 'error', 'message' => $err] : ['status' => 'ok', 'blocked' => $block === '1'];
    }
}
