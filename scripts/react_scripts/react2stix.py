try:
    from scripts.atcutils import ATCutils
except:
    from atcutils import ATCutils

from stix2 import MemoryStore, CustomObject, properties

ATCconfig = ATCutils.load_config("config.yml")
local_react_json_url = ATCconfig.get('local_react_json_url')
react_web_kb_base_url = ATCconfig.get('react_web_kb_base_url')

stix_mem = MemoryStore()

@CustomObject('x-react-stage', [ 
    ( 'name', properties.StringProperty(required=True)), 
    ( 'description', properties.StringProperty()),
    ( 'external_references', properties.ObjectReferenceProperty())] )
class ReactStage(object):
    def __init__(self, name=None, **kwargs):
        list_of_stages = ['Preparation','Identification','Containment','Eradication','Recovery','Lessons Learned']
        if name and name not in list_of_stages:
            raise ValueError("'%s' is not a recognized stage of RE&CT." % name)


@CustomObject( 'x-react-action', [ 
    ( 'name', properties.StringProperty(required=True)), 
    ( 'description', properties.StringProperty()), 
    ( 'external_references', properties.ObjectReferenceProperty()),
    ( 'kill_chain_phases', properties.ListProperty(properties.DictionaryProperty)) ] )
class ReactAction(object):
    def __init__(self, name=None, **kwargs):
        pass


@CustomObject('x-react-matrix', [ 
    ( 'name', properties.StringProperty(required=True)), 
    ( 'description', properties.StringProperty()), 
    ( 'tactic_refs', properties.ListProperty(properties.StringProperty)) ] )
class ReactMatrix(object):
    def __init__(self, name=None, **kwargs):
        pass


external_references = []

for i in range(1,7):
    external_references.append([{
        "source_name": "atc-react",
        "external_id": "RS000" + str(i),
        "url": react_web_kb_base_url + "Response_Stages/" + "RS000" + str(i)
    }])


# define stages order
preparation = ReactStage(name="Preparation", external_references=external_references[0], description="description", x_react_shortname="preparation", allow_custom=True )
identification = ReactStage(name="Identification", external_references=external_references[1], description="description", x_react_shortname="identification" , allow_custom=True )
containment = ReactStage(name="Containment", external_references=external_references[2], description="description", x_react_shortname="containment" , allow_custom=True )
eradication = ReactStage(name="Eradication", external_references=external_references[3], description="description", x_react_shortname="eradication" , allow_custom=True )
recovery = ReactStage(name="Recovery", external_references=external_references[4], description="description", x_react_shortname="recovery" , allow_custom=True )
lessons_learned = ReactStage(name="Lessons Learned", external_references=external_references[5], description="description", x_react_shortname="lessons-learned" , allow_custom=True )

tactic_refs = []

for i in preparation, identification, containment, eradication, recovery, lessons_learned:
    tactic_refs.append(i.id)

react_matrix = ReactMatrix(name='RE&CT Matrix', description='The full RE&CT Matrix, without any mappings but names', tactic_refs=tactic_refs)

class GenerateSTIX:

   def __init__(self, ra=False, rp=False, auto=False,
                 ra_path=False, rp_path=False,
                 atc_dir=False, init=False):
        """Init"""

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir
        else:
            self.atc_dir = ATCconfig.get('md_name_of_root_directory') + '/'

        # Main logic
        if auto:
            self.response_action(ra_path)
            self.response_playbook(rp_path)

        if ra:
            self.response_action(ra_path)

        if rp:
            self.response_playbook(rp_path)

        if ra_path:
            ras, ra_paths = ATCutils.load_yamls_with_paths(ra_path)
        else:
            ras, ra_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_actions_dir'))

        if rp_path:
            rps, rp_paths = ATCutils.load_yamls_with_paths(rp_path)
        else:
            rps, rp_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_playbooks_dir'))

        
        ra_filenames = [ra_path.split('/')[-1].replace('.yml', '') for ra_path in ra_paths]
        rp_filenames = [rp_path.split('/')[-1].replace('.yml', '') for rp_path in rp_paths]

        _preparation = []
        _identification = []
        _containment = []
        _eradication = []
        _recovery = []
        _lessons_learned = []

        stages = [
            ('preparation', _preparation), ('identification', _identification),
            ('containment', _containment), ('eradication', _eradication),
            ('recovery', _recovery), ('lessons_learned', _lessons_learned)
        ]

        for i in range(len(ras)):

            normalized_title = ATCutils.normalize_react_title(ras[i].get('title'))

            ra_updated_title = ras[i].get('id')\
                + ":"\
                + normalized_title
            
            if "RA1" in ras[i]['id']:
                stage = 'preparation'
            elif "RA2" in ras[i]['id']:
                stage = 'identification'
            elif "RA3" in ras[i]['id']:
                stage = 'containment'
            elif "RA4" in ras[i]['id']:
                stage = 'eradication'
            elif "RA5" in ras[i]['id']:
                stage = 'recovery'
            elif "RA6" in ras[i]['id']:
                stage = 'lessons-learned'

            kill_chain_phases = [{
                "kill_chain_name": 'atc-react',
                "phase_name": stage
            }]

            external_references = [{
                "source_name": "atc-react",
                "external_id": ras[i].get('id'),
                "url": react_web_kb_base_url + "Response_Actions/" + ra_filenames[i]
            }]

            ra = ReactAction(
                name=normalized_title, 
                description=ras[i].get('description'),
                external_references=external_references,
                kill_chain_phases=kill_chain_phases,
                x_mitre_platforms=['Windows', 'Linux', 'macOS'],
                allow_custom=True
            )

            stix_mem.add(ra)

        stix_mem.add( [ preparation, 
                        identification,
                        containment,
                        eradication,
                        recovery,
                        lessons_learned
        ])

        stix_mem.add(react_matrix)

        try:
            stix_mem.save_to_file(local_react_json_url)
            print("[+] Created react.json STIX file")
        except:
            print("[-] Failed to create react.json STIX file")
