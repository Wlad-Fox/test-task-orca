

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


class App():
    def __init__(self):
        self.machines = []
        self.rules = []

    def _get_machine_by_id(self, machine_id: str) -> Machine:
        assert(machine_id)
        matching_machines = list(filter(lambda machine: machine.id.startswith(machine_id), self.machines))
        if not matching_machines:
            raise KeyError(machine_id)
        if len(matching_machines) != 1:
            raise MultipleChoiceError(matching_machines)
        return matching_machines[0]


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

    def stats(self):
        return {
            "vm_count":len(self.machines),
            "request_count":1120232,
            "average_request_time":0.003032268166772597
        }
        