import jsonrpc2_zeromq


def promote(endpoint, promotion_req):
    c = jsonrpc2_zeromq.RPCNotifierClient(endpoint, timeout=120*1000)
    r = promotion_req
    try:
        return True, c.copy(
            package=r.package_name, to_codename=r.to_codename,
            to_component=r.component, codename=r.from_codename,
            component=r.component, versions=[r.version],
            cache_control="max-age=0", preserve_versions=True,
            bucket=r.bucket, arch=r.arch)
    except jsonrpc2_zeromq.RPCError as e:
        return False, e.error_msg
