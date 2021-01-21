from functools import wraps
from time import perf_counter


class FirewallAllowRule:
    def __init__(self, id, source, dest):
        self.id = id
        self.source = source
        self.dest = dest

        
class Machine:
    def __init__(self, id, name, tags):
        self.id = id
        self.name = name
        self.tags = set(tags)


class MultipleChoiceError(BaseException):
    pass 


def _log_time(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        start_s = perf_counter()
        try:
            return fn(self, *args, **kwargs)
        finally:
            time_s = perf_counter() - start_s
            self._average_request_time_s = \
                ((self._average_request_time_s * self._requests_count + time_s) /
                (self._requests_count + 1))
            self._requests_count += 1  
    return wrapped


class App():
    def __init__(self):
        self.machines = []
        self.rules = []
        self._requests_count = 0
        self._average_request_time_s = 0

    def _get_machine_by_id(self, machine_id: str) -> Machine:
        assert(machine_id)
        matching_machines = list(filter(lambda machine: machine.id.startswith(machine_id), self.machines))
        if not matching_machines:
            raise KeyError(machine_id)
        if len(matching_machines) != 1:
            raise MultipleChoiceError(matching_machines)
        return matching_machines[0]

    @_log_time
    def get_attack_vectors(self, machine_id): 
        victim = self._get_machine_by_id(machine_id)

        attacker_tags = set(
            rule.source 
            for rule in self.rules 
            if rule.dest in victim.tags
        )

        attacker_ids = [
            machine.id 
            for machine in self.machines 
            if (machine.id != victim.id) and (not machine.tags.isdisjoint(attacker_tags))
        ]

        return attacker_ids

    @_log_time
    def stats(self):
        return {
            "vm_count": len(self.machines),
            "request_count": self._requests_count,
            "average_request_time": self._average_request_time_s * 1000,
        }
        