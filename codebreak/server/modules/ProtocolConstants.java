package codebreak.server.modules;

public interface ProtocolConstants {
    public static final int MNG_CONTROL_FIRST = 2000;
    public static final int MNG_GET_CONNECTIONS = 2000;
    public static final int MNG_CONNECTIONS = 2001;
    public static final int MNG_GET_STATS = 2002;
    public static final int MNG_STATS = 2003;
    public static final int MNG_SHUTDOWN = 2004;
    public static final int MNG_PROJECT_MIGRATE = 2005;
    public static final int MNG_PROJECT_MIGRATE_REPLY = 2006;
    public static final int MNG_MIGRATE_REPLY_SUCCESS = 0;
    public static final int MNG_MIGRATE_REPLY_FAIL = 1;
    public static final int MNG_MIGRATE_UPDATE = 2007;
}
