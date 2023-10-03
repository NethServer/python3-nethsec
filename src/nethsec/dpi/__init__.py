import json
import subprocess


def __load_applications() -> dict[int, str]:
    applications = dict[int, str]()
    with open('/etc/netify.d/netify-apps.conf', 'r') as file:
        for line in file.readlines():
            if line.startswith('app'):
                line_split = line.strip().removesuffix('\n').removeprefix('app:').split(":")
                applications[int(line_split[0])] = line_split[1].split('.')[1]
    return applications


def __load_application_categories() -> dict[int, dict[str, str]]:
    categories = dict[int, dict[str, str]]()
    with open('/etc/netify.d/netify-categories.json', 'r') as file:
        categories_file = json.JSONDecoder().decode(file.read())

        categories_application_tag_index: dict[str, int] = categories_file['application_tag_index']
        categories_names = dict[int, str]()
        for category_name, category_id in categories_application_tag_index.items():
            categories_names[category_id] = category_name

        categories_application_index: list[int, list[int]] = categories_file['application_index']
        for category_id, applications_id in categories_application_index:
            for application_id in applications_id:
                categories[application_id] = {
                    'id': str(category_id),
                    'name': categories_names[category_id]
                }

    return categories


def __load_protocols() -> dict[int, str]:
    result = subprocess.run(['netifyd', '--dump-protos'], check=True, capture_output=True)
    protocols = dict[int, str]()
    for line in result.stdout.decode().splitlines():
        if len(line) < 1:
            continue
        line_split = line.split(":")
        protocols[int(line_split[0].strip())] = line_split[1].strip()

    return protocols


def __load_protocol_categories() -> dict[int, dict[str, str]]:
    categories = dict[int, dict[str, str]]()
    with open('/etc/netify.d/netify-categories.json', 'r') as file:
        categories_file = json.JSONDecoder().decode(file.read())

        categories_protocol_tag_index: dict[str, int] = categories_file['protocol_tag_index']
        categories_names = dict[int, str]()
        for category_name, category_id in categories_protocol_tag_index.items():
            categories_names[category_id] = category_name

        categories_protocol_index: list[int, list[int]] = categories_file['protocol_index']
        for category_id, protocol_ids in categories_protocol_index:
            for protocol_id in protocol_ids:
                categories[protocol_id] = {
                    'id': str(category_id),
                    'name': categories_names[category_id]
                }

    return categories


def index_applications(search: str = None, limit: int = None, page: int = 1) -> list[dict[str, str]]:
    """
    List applications available for filtering.

    Args:
        search: search string
        limit: limit the number of results
        page: page number

    Returns:
        list of dicts, each dict contains the property `code` and `name`
    """
    result = list[dict[str, str]]()
    applications = __load_applications()
    application_categories = __load_application_categories()

    for application_id, application_name in applications.items():
        result.append({
            'id': str(application_id),
            'name': application_name,
            'type': 'application',
            'category': application_categories[application_id]
        })

    protocols = __load_protocols()
    protocol_categories = __load_protocol_categories()

    for protocol_id, protocol_name in protocols.items():
        result.append({
            'id': str(protocol_id),
            'name': protocol_name,
            'type': 'protocol',
            'category': protocol_categories[protocol_id]
        })

    if search is not None:
        search = search.lower()
        result = [item for item in result if
                  item.get('name', '').lower().startswith(search) or
                  item.get('category', {}).get('name', '').lower().startswith(search)]
    if limit is not None:
        result = result[limit * (page - 1):limit * page]

    return result
