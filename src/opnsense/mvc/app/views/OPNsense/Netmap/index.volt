<link rel="stylesheet" type="text/css" href="{{ cache_safe('/ui/css/netmap.css') }}&amp;nm={{ assetVersion }}">
<script src="{{ cache_safe('/ui/js/netmap/netmap.js') }}&amp;nm={{ assetVersion }}"></script>
<script>
    $(document).ready(function () {
        Netmap.start($('#netmap-root'));
    });
</script>
<div id="netmap-root" class="netmap"></div>
