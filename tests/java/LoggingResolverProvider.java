// 仅用于测试：把 JVM 实际发起的域名解析打印出来，证明 URLDNS 真的触发了 DNS。
// Java 18+ 的 InetAddressResolverProvider SPI。
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.stream.Stream;

public class LoggingResolverProvider extends InetAddressResolverProvider {
    @Override
    public InetAddressResolver get(Configuration configuration) {
        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy policy)
                    throws UnknownHostException {
                System.err.println("[RESOLVER-LOOKUP] " + host);
                return Stream.of(InetAddress.getLoopbackAddress());
            }

            @Override
            public String lookupByAddress(byte[] addr) {
                return "stub";
            }
        };
    }

    @Override
    public String name() {
        return "shirokit-testing-resolver";
    }
}
