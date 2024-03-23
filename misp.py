import pymisp

# MISPEvent
# load_file(event_path)
# load(json_event)
# add_attribute(type, value, **kwargs)
# add_object(obj=None, **kwargs)
# add_attribute_tag(tag, attribute_identifier)
# get_attribute_tag(attribute_iden
# add_tag(tag=None, **kwargs)

# MISPObject
# add_attribute(object_relation, **value)
# add_reference(referenced_uuid, relationship_type,
# comment=None, **kwargs)
# has_attributes_by_relation(list_of_relations)
# get_attributes_by_relation(object_relation)
# attributes[], relations[]
# edited, all other paramaters of the MISPObject element
# (name, comment, ...)

# MISPAttribute
# add_tag(tag=None, **kwargs)
# delete()
# malware_binary (if relevant)
# tags[]

# self.attribute = {'to_ids': True}
# misp_event.add_tag(submission['classification'].lower())

# create file object ( file_object = MISPObject('file'))
#     add attribute to file object (file_object.add_attribute(value=file_info[feature], **attribute))
# add references to file object  (from mapping fields ) 
# add object to Event 





class MISP_OPER:
    distribution = 0
    threat_level = 4
    analysis = 0
    tag = "AL"
    content_type = "json"

    def __init__(self, url, apikey, content_type, distribution, tag):
        self.distribution = distribution
        self.tag = tag
        self.content_type = content_type 
        self.misp = pymisp.PyMISP(url, apikey, False)

    def add_event(jsondata):
        self.event = self.misp.add_event(jsondata)

   # Create attributes
    attributes = []
    for f in files:
        a = MISPAttribute()
        a.type = arg_type
        a.value = f.name
        a.data = f
        a.comment = args.comment
        a.distribution = args.distrib
        if args.expand and arg_type == 'malware-sample':
            a.expand = 'binary'
        attributes.append(a)


        m = MISPEvent()
        m.info = args.info
        m.distribution = args.distrib
        m.attributes = attributes
        if args.expand and arg_type == 'malware-sample':
            m.run_expansions()
        misp.add_event(m)




    def add_attribute_to_event(value, category, type, comment, to_ids, tags):
        misp_attribute = MISPAttribute()
        misp_attribute.value = str(value)
        misp_attribute.category = str(category)
        misp_attribute.type = str(type)
        misp_attribute.comment = str(comment)
        misp_attribute.to_ids = str(ids)
        for x in tags:
                misp_attribute.add_tag(x)
        r = pymisp.add_attribute(self.event, misp_attribute)


    def upload_sample();
         


    #to do  de convertit AL ontology (file, service, results, classification, max_score to misp attribute.)