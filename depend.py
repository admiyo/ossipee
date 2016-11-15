'''
Copyright Adam Young  2012-2016

'''

import logging
from keystoneclient.openstack.common.apiclient import exceptions


"""
At the start of an application,  the
factories used to create instances of the various types of classes get
registered with an associated scope.  Scope and Resolvers are tightly coupled
objects.  The clients of the resolver code should request an instance from the
shortest lived resolver:  Request scoped.  When the client  requests an
instance of a registered object, the scopes are searched from shortest lived to
longest lived.  In the enumeration below,  that is from Request to Session to
Global.

The application will only have a single Resolver of a Global scope.

Session support is optional.  If session support is required,  set the Global
Variable RESOLVER_SESSION_SUPPORT=True.
When a new request comes in, it either has enough information to link it up
with an existing Session scoped Resolver,  or it will create a new one.

Since sessions are often timed controlled,  the sessions associated with the
request will often turn out to be stale. In this case, a new session scoped
resolver is instantiated.

"""

scope_map = dict()


class Scope(object):
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.proxy_map = dict()
        scope_map[self.name] = self.proxy_map

scope_map = {}
GLOBAL_SCOPE = Scope("Global")

SESSION_SCOPE = Scope("Session", GLOBAL_SCOPE)

REQUEST_SCOPE = Scope("Request", SESSION_SCOPE)


def register(clazz, proxy, scope=GLOBAL_SCOPE):
    proxy_map = scope_map[scope.name]
    proxy_map[clazz] = proxy


# Allow a way to create a specific instance of a class
def register_named(clazz, name, proxy, scope=GLOBAL_SCOPE):
    proxy_map = scope_map[scope.name]
    proxy_map[(clazz, name)] = proxy


class Resolver(object):
    '''
    classdocs
    '''
    instances = dict()

    def __init__(self, scope=GLOBAL_SCOPE, parent=None):
        self.factories = scope_map[scope.name]
        self.parent = parent

    def resolve(self, clazz, name=None):
        if name is not None:
            return self.resolve_named(clazz, name)
        if (clazz in self.instances):
            return self.instances[clazz]
        if clazz in self.factories:
            factory = self.factories[clazz]

            # TODO: some factory blows up when we are strict here.
            # but we should never call an unnamed factory with a name.
            try:
                inst = factory(self)
            except TypeError as e:
                inst = factory(self, None)
            self.instances[clazz] = inst
            return inst
        if self.parent is not None:
            return self.parent.resolve(clazz)
        else:
            raise KeyError(clazz)

    def resolve_named(self, clazz, name):
        if ((clazz, name) in self.instances):
            return self.instances[(clazz, name)]
        if (clazz, name) in self.factories:
            factory = self.factories[(clazz, name)]
            # Some Factories need the name passed in, some don't.
            # To be nice to the factory writers, we let them decided.
            try:
                inst = factory(self, name)
            except TypeError as b:
                inst = factory(self, name)
            self.instances[(clazz, name)] = inst
            return inst
        elif clazz in self.factories:
            inst = self.factories[clazz](self, name)
            self.instances[(clazz, name)] = inst
            return inst
        if self.parent is not None:
            return self.parent.resolve_named(clazz, name)
        else:
            raise KeyError(clazz)


global_resolver = Resolver(GLOBAL_SCOPE)


class WorkItemList(object):

    def __init__(self, work_items, resolver, factories=True):
        if factories:
            self.work_items = [factory(resolver) for factory in work_items]
        else:
            self.work_items = work_items

    def create(self):
        for item in self.work_items:
            logging.info(item.__class__.__name__)
            item.create()

    def teardown(self):
        for item in reversed(self.work_items):
            logging.info(item.__class__.__name__)

            try:
                item.teardown()
            except exceptions.Conflict:
                logging.info(
                    'Teardown of work item failed. ' +
                    'Waiting 1 second to try again.')
                time.sleep(1)
                item.teardown()

    def display(self):
        for item in self.work_items:
            logging.info(item.__class__.__name__)
            item.display()


class NamedComponentList(WorkItemList):
    def __init__(self, resolver, components, name):
        self.work_items = [resolver.resolve(component, name)
                           for component in components]


class UnnamedComponentList(WorkItemList):
    def __init__(self, resolver, components):
        self.work_items = [resolver.resolve(component)
                           for component in components]
