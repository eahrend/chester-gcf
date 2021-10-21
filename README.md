# CHESTER-GCF

Google cloud function that listens for webhooks from stackdriver monitoring, creates an event in datastore for persistence then sends a message to pub/sub so the daemon can update.


## TODO
Since the models package is open source we can use that rather than a vendors folder.