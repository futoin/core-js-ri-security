'use strict';

const $as = require( 'futoin-asyncsteps' );
const invoker_module = require( 'futoin-invoker' );
const executor_module = require( '../../lib/main' );
const ServiceApp = require( '../../ServiceApp' );
const util = require( 'util' );

const opts = {
    config: {
        domains: [
            'example.com',
        ],
        auth_service: true,
        clear_auth: true,
        mac_auth: true,
    },
    storagePassword: 'e3b694af320229f9b464a358eae063a8',
    publicExecutorOptions : {
        prodMode : true,
        specDirs : __dirname + '/../specs',
        httpAddr : '127.0.0.1',
        httpPort : 34567,
        httpPath : '/stress/',
        httpBacklog : 4096,
        messageSniffer_disabled : function( info, rawmsg, isreq ) {
            console.dir( rawmsg );
        },
    },
    privateExecutorOptions : {
        prodMode : true,
    },
    ccmOptions : {
        prodMode : true,
    },
    databaseConfig: ( () => {
        switch ( process.env.SPI_DB_TYPE ) {
        case 'mysql':
            return {
                DB_FTNSEC_TYPE: 'mysql',
                DB_FTNSEC_HOST: '127.0.0.1',
                DB_FTNSEC_PORT: '3306',
                DB_FTNSEC_USER: 'ftntest',
                DB_FTNSEC_DB: 'ftnsec',
            };
        case 'postgresql':
            return {
                DB_TYPE: 'postgresql',
                DB_HOST: '127.0.0.1',
                DB_PORT: '5432',
                DB_USER: 'ftntest',
                DB_PASS: 'test',
                DB_DB: 'postgres',
            };
        case 'sqlite':
            return {
                DB_FTNSEC_TYPE: 'sqlite',
                DB_FTNSEC_SOCKET: `${__dirname}/../ftnsec.db`,
            };
        default:
            throw new Error( 'Unknown SPI_DB_TYPE' );
        }
    } )(),
};


function print_stats() {
    const mem = process.memoryUsage();

    console.log( "SERVER MEMUSED:"+mem.heapUsed+"/"+mem.heapTotal+"@"+mem.rss );
}

const impl = new class {
    normalCall( as, reqinfo ) {
        reqinfo.result().b = reqinfo.params().a;
    }

    noResult( as, reqinfo ) {}

    errorCall( as, reqinfo ) {
        as.error( 'MyError' );
    }

    rawUpload( as, reqinfo ) {
        reqinfo.result().b = reqinfo.params().a;
    }
};

$as().add(
    ( as ) => {
        const app = new ServiceApp( as, opts );
        const ccm = app.ccm();
        as.add( ( as ) => {
            const manage = ccm.iface( '#ftnsec.manage' );
            const stls_mng = ccm.iface( '#ftnsec.stls.manage' );
            const system_id = app._scope.system_local_id;

            manage.ensureUser( as, 'basicuser', 'example.com' );
            as.add( ( as, res ) => {
                as.state.basicuser = res;
                stls_mng.genNewSecret( as, res, system_id, false );
            } );
            as.add( ( as, new_secret ) => {
                as.state.basicpass = new_secret;
            } );

            manage.ensureService( as, 'hmacuser', 'example.com' );
            as.add( ( as, res ) => {
                as.state.hmacuser = res;
                stls_mng.genNewSecret( as, res, system_id, true );
            } );
            as.add( ( as, new_secret ) => {
                as.state.hmacpass = new_secret;
            } );
        } );

        const executor = app.executor();

        executor.register( as, 'spi.test:0.1', impl );

        executor.on( 'ready', function() {
            print_stats();

            setInterval( print_stats, 1e3 );
        } );
        as.add( ( as ) => process.send( {
            ready : 'ok',
            basicuser : as.state.basicuser,
            basicpass : as.state.basicpass,
            hmacuser : as.state.hmacuser,
            hmacpass : as.state.hmacpass,
        } ) );
    },
    ( as, err ) => {
        console.log( err + " " + as.state.error_info );
        console.log( as.state.last_exception.stack );
    }
).execute();
