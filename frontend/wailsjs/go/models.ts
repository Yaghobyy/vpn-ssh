export namespace main {
	
	export class AppSettings {
	    host: string;
	    port: number;
	    username: string;
	    password: string;
	    privateKey: string;
	    proxyPort: number;
	    mode: string;
	    dns: string[];
	    useIPv6: boolean;
	    authMethod: string;
	
	    static createFrom(source: any = {}) {
	        return new AppSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.privateKey = source["privateKey"];
	        this.proxyPort = source["proxyPort"];
	        this.mode = source["mode"];
	        this.dns = source["dns"];
	        this.useIPv6 = source["useIPv6"];
	        this.authMethod = source["authMethod"];
	    }
	}
	export class ConnectRequest {
	    host: string;
	    port: number;
	    username: string;
	    password: string;
	    privateKey: string;
	    proxyPort: number;
	    mode: string;
	    dns: string[];
	    useIPv6: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ConnectRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.privateKey = source["privateKey"];
	        this.proxyPort = source["proxyPort"];
	        this.mode = source["mode"];
	        this.dns = source["dns"];
	        this.useIPv6 = source["useIPv6"];
	    }
	}
	export class ConnectionStatus {
	    state: string;
	    address: string;
	    proxy: string;
	    message: string;
	    uploadBytes: number;
	    downloadBytes: number;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.address = source["address"];
	        this.proxy = source["proxy"];
	        this.message = source["message"];
	        this.uploadBytes = source["uploadBytes"];
	        this.downloadBytes = source["downloadBytes"];
	    }
	}

}

