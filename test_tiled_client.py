from tiled.client import from_uri

client = from_uri("http://localhost:8407")

# Collect references to active subscriptions. Otherwise, Python may
# garbage collect them, and they will never run.
subs = []

def on_child_created(update):
    "Called when a new entry is created in the container"
    print(f"New item named {update.key}")
    child_sub = update.child().subscribe()
    child_sub.new_data.add_callback(on_new_data)
    child_sub.start_in_thread(start=0)
    subs.append(child_sub)  # Keep a reference.

def on_new_data(update):
    "Called when new data is uploaded or registered for this entry"
    print(f"New data: {update.data()}")

sub = client.subscribe()
sub.child_created.add_callback(on_child_created)
sub.start_in_thread()
