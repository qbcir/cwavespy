'use strict';

var express = require('express');
var waves_tx = require ('@waves/waves-transactions');

var _tx_handlers = {
    3: waves_tx.issue,
    4: waves_tx.transfer,
    5: waves_tx.reissue,
    6: waves_tx.burn,
    7: waves_tx.exchange,
    8: waves_tx.lease,
    9: waves_tx.cancelLease,
    10: waves_tx.alias,
    11: waves_tx.massTransfer,
    12: waves_tx.data,
    13: waves_tx.setScript,
    14: waves_tx.sponsorship,
    15: waves_tx.setAssetScript,
    16: waves_tx.invokeScript
}

var app = express();

app.use(express.json());

app.post('/serialize', function(request, response) {
    try {
        var params = request.body;
        var tx_handler = _tx_handlers[params.type];
        var tx_data = tx_handler(params);
        var serialized_tx = waves_tx.serialize(tx_data);
        var res = {
	    'tx': tx_data,
            'bin': serialized_tx.reduce((a, n) => a + Number(n).toString(16).padStart(2,'0'), '')
        }
        response.send(res);
    } catch (e) {
        response.status(400);
        response.send({'error' : e.message})
    }
});

var port = process.env.port || 3000;
app.listen(port)

