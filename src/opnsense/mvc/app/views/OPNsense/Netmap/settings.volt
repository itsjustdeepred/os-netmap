<script>
    $(document).ready(function () {
        mapDataToFormUI({'frm_settings': '/api/netmap/settings/get'}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });
        $('#saveAct').click(function () {
            const $btn = $(this);
            $btn.prop('disabled', true);
            saveFormToEndpoint('/api/netmap/settings/set', 'frm_settings', function () {
                $btn.prop('disabled', false);
                $('#saveMsg').removeClass('hidden text-danger').addClass('text-success').text("{{ lang._('Saved. Reload the map to use the new settings.') }}");
            }, true, function () {
                $btn.prop('disabled', false);
            });
        });
        $('#testAct').click(function () {
            const $out = $('#testMsg').removeClass('text-success text-danger').text("{{ lang._('Saving and asking AdGuard Home...') }}");
            saveFormToEndpoint('/api/netmap/settings/set', 'frm_settings', function () {
                ajaxGet('/api/netmap/adguard/test', {}, function (data) {
                    if (data && data.status === 'ok') {
                        $out.addClass('text-success').text("{{ lang._('AdGuard Home answers') }}" + (data.version ? ' (' + data.version + ')' : '') +
                            (data.protection ? '' : " - {{ lang._('protection is off') }}"));
                    } else {
                        $out.addClass('text-danger').text((data && data.message) || 'no answer');
                    }
                });
            }, true);
        });
    });
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': settingsForm, 'id': 'frm_settings']) }}
</div>
<div class="content-box" style="padding: 12px 15px;">
    <button class="btn btn-success" id="saveAct" type="button"><i class="fa fa-check"></i> {{ lang._('Save') }}</button>
    <button class="btn btn-default" id="testAct" type="button"><i class="fa fa-plug"></i> {{ lang._('Test AdGuard Home') }}</button>
    <span id="saveMsg" class="hidden" style="margin-left: 10px;"></span>
    <span id="testMsg" style="margin-left: 10px;"></span>
</div>
